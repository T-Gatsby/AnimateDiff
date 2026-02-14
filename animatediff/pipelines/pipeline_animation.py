# Adapted from https://github.com/showlab/Tune-A-Video/blob/main/tuneavideo/pipelines/pipeline_tuneavideo.py

import inspect
from typing import Callable, List, Optional, Union
from dataclasses import dataclass

import numpy as np
import torch
from tqdm import tqdm

from diffusers.utils import is_accelerate_available
from packaging import version
from transformers import CLIPTextModel, CLIPTokenizer

from diffusers.configuration_utils import FrozenDict
from diffusers.models import AutoencoderKL
from diffusers.pipeline_utils import DiffusionPipeline
from diffusers.schedulers import (
    DDIMScheduler,
    DPMSolverMultistepScheduler,
    EulerAncestralDiscreteScheduler,
    EulerDiscreteScheduler,
    LMSDiscreteScheduler,
    PNDMScheduler,
)
from diffusers.utils import deprecate, logging, BaseOutput

from einops import rearrange # 用于张量操作的重排库

from ..models.unet import UNet3DConditionModel
from ..models.sparse_controlnet import SparseControlNetModel
import pdb # Python 调试器

logger = logging.get_logger(__name__)  # 创建日志记录器


@dataclass
class AnimationPipelineOutput(BaseOutput):
    #定义管道输出数据类
    videos: Union[torch.Tensor, np.ndarray]  # 输出的视频数据 可以是张量或numpy数组


class AnimationPipeline(DiffusionPipeline):
    """
    动画生成管道类
    基于扩散模型生成文本到视频的动画
    继承自DiffusionPipeline，提供标准化的扩散模型接口
    """
    _optional_components = [] # 定义可选组件列表，当前为空

    """
        初始化动画管道
        参数:
            vae: 变分自编码器，用于潜在空间编码
            text_encoder: 文本编码器，生成文本嵌入
            tokenizer: 文本分词器
            unet: 3D UNet条件模型，核心生成模型
            scheduler: 扩散调度器，控制生成过程
            controlnet: 可选的ControlNet，提供空间控制
    """
    def __init__(
        self,
        vae: AutoencoderKL, # 变分自编码器，用于潜在空间编码和解码
        text_encoder: CLIPTextModel, # 文本编码器：将文本提示转换为嵌入向量
        tokenizer: CLIPTokenizer, # 文本分词器 ：处理文本输入，转换为token
        unet: UNet3DConditionModel, # 3D UNet 模型：核心的扩散模型，处理时空数据
        scheduler: Union[ # 扩散调度器：控制扩散过程中的噪声添加和去除
            DDIMScheduler,
            PNDMScheduler,
            LMSDiscreteScheduler,
            EulerDiscreteScheduler,
            EulerAncestralDiscreteScheduler,
            DPMSolverMultistepScheduler,
        ],
        controlnet: Union[SparseControlNetModel, None] = None, # 可选的ControlNet模型：提供额外的控制条件
    ):
        super().__init__() # ← 调用 父类 DiffusionPipeline.__init__()
         
        # 检查steps_offset 调度器配置检查和更新，确保兼容性
        if hasattr(scheduler.config, "steps_offset") and scheduler.config.steps_offset != 1:
            # 构建弃用警告信息
            deprecation_message = (
                f"The configuration file of this scheduler: {scheduler} is outdated. `steps_offset`"
                f" should be set to 1 instead of {scheduler.config.steps_offset}. Please make sure "
                "to update the config accordingly as leaving `steps_offset` might led to incorrect results"
                " in future versions. If you have downloaded this checkpoint from the Hugging Face Hub,"
                " it would be very nice if you could open a Pull request for the `scheduler/scheduler_config.json`"
                " file"
            )
            # 发出弃用警告
            deprecate("steps_offset!=1", "1.0.0", deprecation_message, standard_warn=False)
            # 创建新配置并更新steps_offset
            new_config = dict(scheduler.config)
            new_config["steps_offset"] = 1
            scheduler._internal_dict = FrozenDict(new_config) # 使用冻结字典存储配置

        # 检查并更新 clip_sample 配置，确保设置为False
        if hasattr(scheduler.config, "clip_sample") and scheduler.config.clip_sample is True:
            deprecation_message = (
                f"The configuration file of this scheduler: {scheduler} has not set the configuration `clip_sample`."
                " `clip_sample` should be set to False in the configuration file. Please make sure to update the"
                " config accordingly as not setting `clip_sample` in the config might lead to incorrect results in"
                " future versions. If you have downloaded this checkpoint from the Hugging Face Hub, it would be very"
                " nice if you could open a Pull request for the `scheduler/scheduler_config.json` file"
            )
            deprecate("clip_sample not set", "1.0.0", deprecation_message, standard_warn=False)
            new_config = dict(scheduler.config)
            new_config["clip_sample"] = False  # 设置为False
            scheduler._internal_dict = FrozenDict(new_config)
        
        # ==================== UNet配置检查和更新 ====================
        # UNet 版本兼容性检查，是否小于0.9.0
        is_unet_version_less_0_9_0 = hasattr(unet.config, "_diffusers_version") and version.parse(
            version.parse(unet.config._diffusers_version).base_version
        ) < version.parse("0.9.0.dev0")
        # 检查UNet样本大小是否小于64
        is_unet_sample_size_less_64 = hasattr(unet.config, "sample_size") and unet.config.sample_size < 64
        if is_unet_version_less_0_9_0 and is_unet_sample_size_less_64:
            # 处理过时的 sample_size 配置，，发出警告并更新配置
            deprecation_message = (
                "The configuration file of the unet has set the default `sample_size` to smaller than"
                " 64 which seems highly unlikely. If your checkpoint is a fine-tuned version of any of the"
                " following: \n- CompVis/stable-diffusion-v1-4 \n- CompVis/stable-diffusion-v1-3 \n-"
                " CompVis/stable-diffusion-v1-2 \n- CompVis/stable-diffusion-v1-1 \n- runwayml/stable-diffusion-v1-5"
                " \n- runwayml/stable-diffusion-inpainting \n you should change 'sample_size' to 64 in the"
                " configuration file. Please make sure to update the config accordingly as leaving `sample_size=32`"
                " in the config might lead to incorrect results in future versions. If you have downloaded this"
                " checkpoint from the Hugging Face Hub, it would be very nice if you could open a Pull request for"
                " the `unet/config.json` file"
            )
            deprecate("sample_size<64", "1.0.0", deprecation_message, standard_warn=False)
            new_config = dict(unet.config)
            new_config["sample_size"] = 64  # 更新样本大小为64
            unet._internal_dict = FrozenDict(new_config)
        
        # ==================== 注册模块组件 ====================
        # 使用register_modules方法注册所有组件，便于管理和序列化
        self.register_modules(
            vae=vae,
            text_encoder=text_encoder,
            tokenizer=tokenizer,
            unet=unet,
            scheduler=scheduler,
            controlnet=controlnet,
        )
        # 计算VAE缩放因子：基于VAE的下采样块数
        # 例如，如果有3个下采样块，缩放因子为2^(3-1)=4
        self.vae_scale_factor = 2 ** (len(self.vae.config.block_out_channels) - 1) # VAE 缩放因子

    def enable_vae_slicing(self):
        """启用VAE切片：通过切片处理大图像以减少内存使用"""
        self.vae.enable_slicing()

    def disable_vae_slicing(self):
        """禁用VAE切片：恢复完整的图像处理"""
        self.vae.disable_slicing()

    def enable_sequential_cpu_offload(self, gpu_id=0):
        """
        启用顺序CPU卸载：将模型按顺序卸载到CPU以节省GPU内存
        
        参数:
            gpu_id: 使用的GPU设备ID
        """
        if is_accelerate_available():  # 检查是否安装了accelerate库
            from accelerate import cpu_offload
        else:
            raise ImportError("Please install accelerate via `pip install accelerate`")

        device = torch.device(f"cuda:{gpu_id}") # 指定GPU设备
        
        # 将模型按顺序卸载到 CPU
        for cpu_offloaded_model in [self.unet, self.text_encoder, self.vae]:
            if cpu_offloaded_model is not None:
                cpu_offload(cpu_offloaded_model, device) # 执行CPU卸载


    @property
    def _execution_device(self):
        """
        获取执行设备属性
        确定模型应该在哪个设备上执行
        """
        # 如果设备不是meta或者UNet没有hook，直接返回设备
        if self.device != torch.device("meta") or not hasattr(self.unet, "_hf_hook"):
            return self.device
        
        # 检查是否有钩子指定了执行设备，遍历UNet的所有模块，查找执行设备hook
        for module in self.unet.modules():
            if (
                hasattr(module, "_hf_hook")  # 检查是否有hook
                and hasattr(module._hf_hook, "execution_device")  # 检查hook是否有执行设备属性
                and module._hf_hook.execution_device is not None  # 检查执行设备是否不为空
            ):
                return torch.device(module._hf_hook.execution_device)  # 返回hook指定的设备
        return self.device  # 返回默认设备

    def _encode_prompt(self, prompt, device, num_videos_per_prompt, do_classifier_free_guidance, negative_prompt):
        # 编码文本提示为嵌入向量
        """
        编码文本提示为嵌入向量
        核心功能：将文本输入转换为模型可以理解的数值表示
        
        参数:
            prompt: 正面提示词（字符串或列表）
            device: 计算设备（CPU/GPU）
            num_videos_per_prompt: 每个提示词生成的视频数量
            do_classifier_free_guidance: 是否进行无分类器指导
            negative_prompt: 负面提示词（字符串或列表）
            
        返回:
            text_embeddings: 文本嵌入向量，形状为 [batch_size * num_videos, sequence_length, hidden_size]
        """
        #确定批次大小：如果是列表就是列表长度，否则为1
        batch_size = len(prompt) if isinstance(prompt, list) else 1
        # ==================== 正面提示词编码 ====================
        # 文本分词，使用tokenizer处理文本输入
        text_inputs = self.tokenizer(
            prompt,  # 输入文本
            padding="max_length", # 填充到最大长度
            max_length=self.tokenizer.model_max_length, # 使用tokenizer的最大长度
            truncation=True, # 启用截断
            return_tensors="pt",# 返回PyTorch张量
        )
        text_input_ids = text_inputs.input_ids  # 获取token IDs
        # 获取未截断的token IDs用于比较
        untruncated_ids = self.tokenizer(prompt, padding="longest", return_tensors="pt").input_ids

        # 检查是否发生了截断，如果发生则发出警告
        if untruncated_ids.shape[-1] >= text_input_ids.shape[-1] and not torch.equal(text_input_ids, untruncated_ids):
            # 获取被截断的部分文本
            removed_text = self.tokenizer.batch_decode(untruncated_ids[:, self.tokenizer.model_max_length - 1 : -1])
            logger.warning(
                "The following part of your input was truncated because CLIP can only handle sequences up to"
                f" {self.tokenizer.model_max_length} tokens: {removed_text}"
            )
        # 注意力掩码处理
        # 根据文本编码器配置决定是否使用注意力掩码
        if hasattr(self.text_encoder.config, "use_attention_mask") and self.text_encoder.config.use_attention_mask:
            attention_mask = text_inputs.attention_mask.to(device) # 将注意力掩码移到设备上
        else:
            attention_mask = None  # 不使用注意力掩码

        # 使用文本编码器生成文本嵌入
        text_embeddings = self.text_encoder(
            text_input_ids.to(device),  # 将token IDs移到设备上
            attention_mask=attention_mask,# 传入注意力掩码（如果有）
        )
        text_embeddings = text_embeddings[0]# 取第一个输出（隐藏状态）

        # 为每个提示复制文本嵌入
        # 获取嵌入向量的形状：[batch_size, sequence_length, hidden_size]
        bs_embed, seq_len, _ = text_embeddings.shape
         # 重复嵌入向量以匹配每个提示词要生成的视频数量
        text_embeddings = text_embeddings.repeat(1, num_videos_per_prompt, 1)
        # 重塑张量形状：[batch_size * num_videos_per_prompt, sequence_length, hidden_size]
        text_embeddings = text_embeddings.view(bs_embed * num_videos_per_prompt, seq_len, -1)

        # 无分类器指导处理 
        # 分类器自由引导：处理负向提示
        # get unconditional embeddings for classifier free guidance
        if do_classifier_free_guidance:
            uncond_tokens: List[str]  # 无条件（负面）提示词的token列表
            # 处理负面提示词的各种情况
            if negative_prompt is None:
                uncond_tokens = [""] * batch_size   # 如果没有提供负面提示词，使用空字符串

            elif type(prompt) is not type(negative_prompt):
                # 检查正面和负面提示词类型是否一致
                raise TypeError(
                    f"`negative_prompt` should be the same type to `prompt`, but got {type(negative_prompt)} !="
                    f" {type(prompt)}."
                )
            
            elif isinstance(negative_prompt, str):
                # 如果负面提示词是字符串，转换为列表
                uncond_tokens = [negative_prompt]

            elif batch_size != len(negative_prompt):
                # 检查批次大小是否匹配
                raise ValueError(
                    f"`negative_prompt`: {negative_prompt} has batch size {len(negative_prompt)}, but `prompt`:"
                    f" {prompt} has batch size {batch_size}. Please make sure that passed `negative_prompt` matches"
                    " the batch size of `prompt`."
                )
            else:
                # 负面提示词已经是正确格式的列表
                uncond_tokens = negative_prompt
            # 编码负向提示
            max_length = text_input_ids.shape[-1]  # 使用正面提示词的最大长度
            # 对负面提示词进行tokenize
            uncond_input = self.tokenizer(
                uncond_tokens,
                padding="max_length", # 填充到最大长度
                max_length=max_length,# 使用相同的最大长度
                truncation=True, # 启用截断
                return_tensors="pt",# 返回PyTorch张量
            )
            # 同样处理注意力掩码
            if hasattr(self.text_encoder.config, "use_attention_mask") and self.text_encoder.config.use_attention_mask:
                attention_mask = uncond_input.attention_mask.to(device)
            else:
                attention_mask = None

            # 编码负面提示词
            uncond_embeddings = self.text_encoder(
                uncond_input.input_ids.to(device),
                attention_mask=attention_mask,
            )
            uncond_embeddings = uncond_embeddings[0] # 取隐藏状态

            # duplicate unconditional embeddings for each generation per prompt, using mps friendly method
            # 重复负面嵌入以匹配生成数量
            seq_len = uncond_embeddings.shape[1]
            uncond_embeddings = uncond_embeddings.repeat(1, num_videos_per_prompt, 1)
            uncond_embeddings = uncond_embeddings.view(batch_size * num_videos_per_prompt, seq_len, -1)

            # 为了效率，将无条件嵌入和条件嵌入拼接成一个批次
            # 这样只需要一次前向传播而不是两次
            # 形状：[2 * batch_size * num_videos_per_prompt, sequence_length, hidden_size]
            text_embeddings = torch.cat([uncond_embeddings, text_embeddings])

        return text_embeddings # 返回最终的文本嵌入

    def decode_latents(self, latents):
        """将潜在变量解码为像素空间"""
        video_length = latents.shape[2]  # 获取视频长度（帧数）
        latents = 1 / 0.18215 * latents  # 缩放潜在变量
   
        # 重新排列维度：从 [batch, channels, frames, height, width] 
        # 变为 [(batch * frames), channels, height, width]以便 VAE 解码
        latents = rearrange(latents, "b c f h w -> (b f) c h w")

        # video = self.vae.decode(latents).sample
        # 逐帧解码以节省内存
        video = [] # 存储解码后的视频帧
        # 使用进度条显示解码进度
        for frame_idx in tqdm(range(latents.shape[0])):
            # 逐帧解码：每次只解码一帧
            video.append(self.vae.decode(latents[frame_idx:frame_idx+1]).sample)
        # 将所有帧拼接起来
        video = torch.cat(video)
        # 重新排列维度：从 [(batch * frames), channels, height, width]
        # 变回 [batch, channels, frames, height, width]
        video = rearrange(video, "(b f) c h w -> b c f h w", f=video_length)
        # 将像素值从[-1,1]范围转换到[0,1]范围
        video = (video / 2 + 0.5).clamp(0, 1) # 归一化到 [0, 1]
        # 转换为float32并移到CPU，numpy数组格式
        # we always cast to float32 as this does not cause significant overhead and is compatible with bfloa16
        video = video.cpu().float().numpy()
        return video

    def prepare_extra_step_kwargs(self, generator, eta):
        """
        准备调度器步骤的额外参数
        不同调度器可能需要不同的参数
        
        参数:
            generator: 随机数生成器
            eta: DDIM调度器的eta参数
            
        返回:
            extra_step_kwargs: 包含额外参数的字典
        """
        # 准备调度器步骤的额外参数，因为不是所有调度器都有相同的签名
        # eta (η) 仅用于DDIMScheduler，对其他调度器会被忽略
        # eta 对应DDIM论文中的η：https://arxiv.org/abs/2010.02502
        # 应该在[0, 1]范围内
        """准备调度器步骤的额外参数"""
        # 检查调度器是否接受 eta 参数
        accepts_eta = "eta" in set(inspect.signature(self.scheduler.step).parameters.keys())

        extra_step_kwargs = {}# 初始化参数字典
        # 检查调度器是否接受eta参数
        if accepts_eta:
            extra_step_kwargs["eta"] = eta # 添加eta参数

        # check if the scheduler accepts generator
        # 检查调度器是否接受生成器
        accepts_generator = "generator" in set(inspect.signature(self.scheduler.step).parameters.keys())
        if accepts_generator:
            extra_step_kwargs["generator"] = generator # 添加生成器参数
        return extra_step_kwargs

    def check_inputs(self, prompt, height, width, callback_steps):
        """
        检查输入参数的合法性
        确保所有输入参数符合模型要求
        
        参数:
            prompt: 文本提示词
            height: 图像高度
            width: 图像宽度
            callback_steps: 回调步数
        """
        # 检查提示词类型
        if not isinstance(prompt, str) and not isinstance(prompt, list):
            raise ValueError(f"`prompt` has to be of type `str` or `list` but is {type(prompt)}")
        
        # 检查高度和宽度是否能被8整除（因为VAE有下采样）
        if height % 8 != 0 or width % 8 != 0:
            raise ValueError(f"`height` and `width` have to be divisible by 8 but are {height} and {width}.")

        # 检查回调步数的合法性
        if (callback_steps is None) or (
            callback_steps is not None and (not isinstance(callback_steps, int) or callback_steps <= 0)
        ):
            raise ValueError(
                f"`callback_steps` has to be a positive integer but is {callback_steps} of type"
                f" {type(callback_steps)}."
            )

    def prepare_latents(self, batch_size, num_channels_latents, video_length, height, width, dtype, device, generator, latents=None):
        """
        准备初始潜在向量
        生成或处理用于扩散过程的初始噪声
        Stable Diffusion 只能处理 4D (Batch, Channel, Height, Width)
        AnimateDiff 必须处理 5D (Batch, Channel, Frames, Height, Width)。
        代码生成初始噪声：shape = (batch_size, num_channels_latents, video_length, height, width)。
        参数:
            batch_size: 批次大小
            num_channels_latents: 潜在向量的通道数
            video_length: 视频长度（帧数）
            height: 图像高度
            width: 图像宽度
            dtype: 数据类型
            device: 计算设备
            generator: 随机数生成器
            latents: 可选的预提供潜在向量
            
        返回:
            latents: 准备好的潜在向量，形状为 [batch_size, num_channels_latents, video_length, height//scale, width//scale]
        """
        # 计算潜在空间的形状（考虑了VAE的缩放因子）
        shape = (batch_size, num_channels_latents, video_length, height // self.vae_scale_factor, width // self.vae_scale_factor)
        # 检查生成器列表的长度是否与批次大小匹配
        if isinstance(generator, list) and len(generator) != batch_size:
            raise ValueError(
                f"You have passed a list of generators of length {len(generator)}, but requested an effective batch"
                f" size of {batch_size}. Make sure the batch size matches the length of the generators."
            )
        # 生成或处理潜在向量
        if latents is None:
            # 如果没有提供潜在向量，生成随机噪声
            # 对于MPS设备（Apple Silicon），在CPU上生成随机数
            rand_device = "cpu" if device.type == "mps" else device

            if isinstance(generator, list):
                # 如果提供了生成器列表，为每个批次元素使用不同的生成器
                shape = shape
                # shape = (1,) + shape[1:]
                latents = [
                    torch.randn(shape, generator=generator[i], device=rand_device, dtype=dtype)
                    for i in range(batch_size)
                ]
                # 将所有批次的潜在向量拼接起来
                latents = torch.cat(latents, dim=0).to(device)
            else:
                # 使用单个生成器生成所有潜在向量
                latents = torch.randn(shape, generator=generator, device=rand_device, dtype=dtype).to(device)
        else:
            # 如果提供了潜在向量，检查形状是否匹配
            if latents.shape != shape:
                raise ValueError(f"Unexpected latents shape, got {latents.shape}, expected {shape}")
            latents = latents.to(device) # 确保在正确的设备上

        # scale the initial noise by the standard deviation required by the scheduler
        # 根据调度器的初始噪声标准差缩放潜在向量
        latents = latents * self.scheduler.init_noise_sigma
        return latents

    @torch.no_grad()
    def __call__(
        self,
        prompt: Union[str, List[str]], # 文本提示词，可以是字符串或字符串列表
        video_length: Optional[int],   # 视频长度（帧数）
        height: Optional[int] = None,  # 输出高度，默认为None（使用UNet配置）
        width: Optional[int] = None,   # 输出宽度，默认为None（使用UNet配置）
        num_inference_steps: int = 50, # 推理步数，控制生成质量与速度的权衡
        guidance_scale: float = 7.5,   # 指导尺度，控制文本条件的影响强度
        negative_prompt: Optional[Union[str, List[str]]] = None,# 负向提示，引导生成远离某些内容
        num_videos_per_prompt: Optional[int] = 1, # 每个提示生成的视频数 # 每个提示词生成的视频数量
        eta: float = 0.0,                         # DDIM 调度器的 eta 参数，控制随机性
        generator: Optional[Union[torch.Generator, List[torch.Generator]]] = None, # 随机数生成器，控制可重复性
        latents: Optional[torch.FloatTensor] = None, # 可选的初始潜在向量，用于控制生成起点
        output_type: Optional[str] = "tensor",       # 输出类型，"tensor"或"numpy"
        return_dict: bool = True,                    # 是否返回字典格式的结果
        callback: Optional[Callable[[int, int, torch.FloatTensor], None]] = None,  # 回调函数 ，用于中间结果监控
        callback_steps: Optional[int] = 1,           # 回调步数间隔

        # support controlnet
        # ControlNet 相关参数
        controlnet_images: torch.FloatTensor = None, # ControlNet控制图像，形状为 [batch, channels, frames, height, width]
        controlnet_image_index: list = [0],          # 控制图像在视频序列中的位置索引
        controlnet_conditioning_scale: Union[float, List[float]] = 1.0, # ControlNet 条件缩放尺度

        **kwargs, # 其他关键字参数，用于向前兼容
    ):
        """
        主要的推理调用方法
        执行从文本到视频的完整生成流程
        """
        # ==================== 参数初始化和验证 ====================
        # Default height and width to unet
        # 设置默认高度和宽度：如果未提供，使用UNet配置的样本大小乘以VAE缩放因子
        height = height or self.unet.config.sample_size * self.vae_scale_factor
        width = width or self.unet.config.sample_size * self.vae_scale_factor

        # Check inputs. Raise error if not correct
        # 检查输入有效性
        self.check_inputs(prompt, height, width, callback_steps)

        # Define call parameters
        # batch_size = 1 if isinstance(prompt, str) else len(prompt)# 原始逻辑
        # 定义调用参数：确定批次大小
        batch_size = 1  # 初始化为1
        if latents is not None:
            # 如果提供了潜在向量，使用其批次大小
            batch_size = latents.shape[0]
        if isinstance(prompt, list):
            # 如果提示词是列表，使用列表长度作为批次大小
            batch_size = len(prompt)

        # 获取执行设备
        device = self._execution_device

        # 这里 `guidance_scale` 的定义类似于Imagen论文中方程(2)的指导权重`w`
        # `guidance_scale = 1` 对应于不进行无分类器指导
        # 当guidance_scale > 1.0时启用无分类器指导
        do_classifier_free_guidance = guidance_scale > 1.0

        # Encode input prompt
        # 编码文本提示，统一提示词格式：确保prompt是列表形式
        prompt = prompt if isinstance(prompt, list) else [prompt] * batch_size

        # 统一负面提示词格式
        if negative_prompt is not None:
            negative_prompt = negative_prompt if isinstance(negative_prompt, list) else [negative_prompt] * batch_size 

        ## 编码文本提示词为嵌入向量
        text_embeddings = self._encode_prompt(
            prompt, device, num_videos_per_prompt, do_classifier_free_guidance, negative_prompt
        )

        # ==================== 调度器时间步准备 ====================
        # 设置调度器时间步
        self.scheduler.set_timesteps(num_inference_steps, device=device)
        timesteps = self.scheduler.timesteps # 获取所有时间步
        
        # ==================== 潜在向量准备 ====================
        # Prepare latent variables
        # 准备初始潜在向量（噪声）  调用unet
        num_channels_latents = self.unet.in_channels  # 获取UNet输入通道数
        latents = self.prepare_latents(
            batch_size * num_videos_per_prompt, # 总批次大小
            num_channels_latents, # 潜在向量通道数
            video_length, # 视频长度
            height,# 高度
            width,# 宽度
            text_embeddings.dtype,# 数据类型（与文本嵌入一致）
            device,# 计算设备
            generator,# 随机数生成器
            latents,# 可选的预提供潜在向量
        )
        latents_dtype = latents.dtype # 保存潜在向量的数据类型

        # Prepare extra step kwargs.
        # 准备调度器步骤的额外参数
        extra_step_kwargs = self.prepare_extra_step_kwargs(generator, eta)

        # Denoising loop
        # 去噪循环，计算预热步数（用于进度条）
        num_warmup_steps = len(timesteps) - num_inference_steps * self.scheduler.order
        # 创建进度条
        with self.progress_bar(total=num_inference_steps) as progress_bar:
            # 遍历所有时间步进行去噪
            for i, t in enumerate(timesteps):
                # ==================== 潜在向量扩展 ====================
                
                # 如果进行无分类器指导，将潜在向量复制两份
                # 一份用于无条件生成，一份用于条件生成
                latent_model_input = torch.cat([latents] * 2) if do_classifier_free_guidance else latents
                # 根据调度器要求缩放模型输入
                latent_model_input = self.scheduler.scale_model_input(latent_model_input, t)
                
                # ControlNet 处理 
                # 初始化ControlNet的额外残差连接
                down_block_additional_residuals = mid_block_additional_residual = None # 下采样块的额外残差和中间块的额外残差

                # 检查是否使用了ControlNet
                if (getattr(self, "controlnet", None) != None) and (controlnet_images != None):
                    assert controlnet_images.dim() == 5 # 确保是 5D 张量 [batch, channels, frames, height, width]

                    # 准备ControlNet的输入
                    controlnet_noisy_latents = latent_model_input  # 噪声潜在向量
                    controlnet_prompt_embeds = text_embeddings     # 文本嵌入

                    # 确保ControlNet图像在正确的设备上
                    controlnet_images = controlnet_images.to(latents.device)

                    # ==================== 控制条件掩码构建 ====================
                    # 准备 ControlNet 条件
                    controlnet_cond_shape    = list(controlnet_images.shape)
                    controlnet_cond_shape[2] = video_length # 设置帧数为视频长度
                    controlnet_cond = torch.zeros(controlnet_cond_shape).to(latents.device)
                    
                    # 创建条件掩码的形状
                    controlnet_conditioning_mask_shape    = list(controlnet_cond.shape)
                    controlnet_conditioning_mask_shape[1] = 1  # 单通道掩码
                    controlnet_conditioning_mask          = torch.zeros(controlnet_conditioning_mask_shape).to(latents.device)

                    # 验证控制图像数量足够
                    assert controlnet_images.shape[2] >= len(controlnet_image_index)
                    # 将控制图像放置在指定的帧位置
                    controlnet_cond[:,:,controlnet_image_index] = controlnet_images[:,:,:len(controlnet_image_index)]
                    # 设置对应位置的掩码为1
                    controlnet_conditioning_mask[:,:,controlnet_image_index] = 1

                    # ==================== ControlNet前向传播 ====================
                    # 调用ControlNet生成额外的残差连接
                    down_block_additional_residuals, mid_block_additional_residual = self.controlnet(
                        controlnet_noisy_latents, t,  # 噪声潜在向量和当前时间步
                        encoder_hidden_states=controlnet_prompt_embeds, # 文本嵌入
                        controlnet_cond=controlnet_cond,  # 控制条件 
                        conditioning_mask=controlnet_conditioning_mask, # 条件掩码
                        conditioning_scale=controlnet_conditioning_scale,  # 条件缩放
                        guess_mode=False, return_dict=False,  # 不使用猜测模式，返回元组而不是字典
                    )

                # ==================== UNet噪声预测 ====================
                # predict the noise residual
                # 使用UNet预测噪声残差  
                noise_pred = self.unet(
                    latent_model_input, t,   # 潜在模型输入，当前时间步
                    encoder_hidden_states=text_embeddings,  # 文本条件嵌入
                    down_block_additional_residuals = down_block_additional_residuals,# ControlNet下采样残差
                    mid_block_additional_residual   = mid_block_additional_residual,# ControlNet中间残差
                ).sample.to(dtype=latents_dtype)  # 确保数据类型一致

                # ==================== 无分类器指导 ====================
                # perform guidance
                # 执行无分类器指导
                if do_classifier_free_guidance:
                    # 将噪声预测分割为无条件部分和条件部分
                    noise_pred_uncond, noise_pred_text = noise_pred.chunk(2)
                    # 根据指导尺度合并两部分预测
                    noise_pred = noise_pred_uncond + guidance_scale * (noise_pred_text - noise_pred_uncond)   #CFG 计算，让生成的画面强行贴近“ToonYou”和“1girl”的描述。

                # ==================== 调度器步骤 ====================
                # compute the previous noisy sample x_t -> x_t-1
                # 计算前一个噪声样本 x_t -> x_t-1
                latents = self.scheduler.step(noise_pred, t, latents, **extra_step_kwargs).prev_sample # 单次循环终点，噪声预测，当前时间步，修正当前的 Latents，额外参数， prev_sample获取前一个样本
                #回到for i, t in enumerate(timesteps): 循环，用修正后的 Latents 再跑一轮。如此循环多次，Latents 从杂乱的雪花点变成了有规律的特征数据。

              
                # 调用回调函数（如果提供了的话）用于监控、展示和外部通信 
                if i == len(timesteps) - 1 or ((i + 1) > num_warmup_steps and (i + 1) % self.scheduler.order == 0):
                    progress_bar.update()  # 更新进度条
                    if callback is not None and i % callback_steps == 0:
                        # 调用回调函数，传入当前步数、时间步和潜在向量/ 外部通信
                        callback(i, t, latents)

        # Post-processing
         # 后处理：解码潜在变量为像素空间视频
        video = self.decode_latents(latents)

        # Convert to tensor
        # 转换为指定输出类型张量
        if output_type == "tensor":
            video = torch.from_numpy(video)  # 转换为PyTorch张量

        # ==================== 返回结果 ====================
        # 根据return_dict参数决定返回格式
        if not return_dict:
            return video  # 直接返回视频张量/数组
        
        # 返回标准化的输出对象
        return AnimationPipelineOutput(videos=video)
