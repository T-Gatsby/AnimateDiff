import argparse                                                        #导入参数解析库，用于处理用户在命令行中输入的参数，如 --config 和 --L 等。
import datetime                                                        #导入日期时间库，用于生成带有时间戳的输出文件夹名。
import inspect                                                         #导入代码检查库，用于在 main 函数中获取当前函数的参数值（但在这里主要用于调试或记录，不是核心功能）。
import os                                                              #导入操作系统接口，用于创建文件夹和处理路径。
from omegaconf import OmegaConf                                        #导入配置管理库，用于加载和处理 YAML 配置文件，如 1_3_animate_ToonYou.yaml
import torch                                                           #深度学习的核心框架。
import torchvision.transforms as transforms                            #导入图像处理工具,torchvision 中的图像预处理和后处理工具

import diffusers                                                       #Hugging Face 的扩散模型库。
from diffusers import AutoencoderKL, DDIMScheduler                     #AutoencoderKL 是 VAE 模型；DDIMScheduler 是其中一个去噪调度器。

from tqdm.auto import tqdm                                             #用于在推理过程中显示进度条。
from transformers import CLIPTextModel, CLIPTokenizer                  #CLIPTextModel 是文本编码器；CLIPTokenizer 是分词器，用于将文本转为数字 ID

from animatediff.models.unet import UNet3DConditionModel               #AnimateDiff 核心修改。导入支持时间维度（3D）条件的 UNet 模型。
from animatediff.models.sparse_controlnet import SparseControlNetModel #导入 ControlNet 模型,可选的 ControlNet 组件，用于条件控制（如边缘、深度图）
from animatediff.pipelines.pipeline_animation import AnimationPipeline #导入动画管道,核心推理流程（定义在 pipeline_animation.py）的封装类。
from animatediff.utils.util import save_videos_grid                    #导入视频保存工具,用于将生成的视频张量保存为 GIF 或 MP4。
from animatediff.utils.util import load_weights, auto_download         #导入权重加载工具,load_weights 是关键函数，用于注入 Motion Module 和 DreamBooth/LoRA 权重
from diffusers.utils.import_utils import is_xformers_available         #导入 xformers 检查工具,检查系统是否安装 xFormers 以开启高效显存注意力。

# [新增] 导入 StegoProcessor
from animatediff.utils.stego import StegoProcessor

from einops import rearrange, repeat                                   #导入张量操作库,用于在不同维度之间高效地重新排列张量（例如 2D <-> 3D 转换）

import csv, pdb, glob, math                                            #glob 用于文件搜索；pdb 用于调试；其余为通用工具。
from pathlib import Path                                               #导入路径操作库,用于更优雅地处理文件路径
from PIL import Image                                                  #导入图像库,用于处理 ControlNet 图像或 VAE 解码后的图像。
import numpy as np                                                     #导入数值计算库,用于处理 NumPy 数组


@torch.no_grad()  #装饰器。由于这是推理（生成）过程而非训练，禁用梯度可以节省内存并提高速度
def main(args):

    #第一步：加载推理配置
    *_, func_args = inspect.getargvalues(inspect.currentframe()) #获取函数参数,使用 inspect 获取当前函数（main）被调用时的所有参数值（主要用于调试或日志记录）
    func_args = dict(func_args)
    
    # ==================== 断点1：程序开始 ====================
    # 这里可以观察命令行参数和初始状态
    print("断点1：程序开始")
    print(f"参数列表: {func_args}")
    print(f"配置文件路径: {args.config}")
    print(f"宽高设置: W={args.W}, H={args.H}, L={args.L}")
    # 断点1 - 观察程序初始状态

    # 创建保存结果的目录
    time_str = datetime.datetime.now().strftime("%Y-%m-%dT%H-%M-%S") #获取当前时间格式化成字符串，例如 2025-11-23T17-15-00
    savedir = f"samples/{Path(args.config).stem}-{time_str}"#定义保存目录
    os.makedirs(savedir) # 创建输出目录

    # ==================== 断点2：加载配置文件后 ====================
    config  = OmegaConf.load(args.config) #配置加载，读取yaml文件
    print("断点2：配置文件已加载")
    print(f"配置类型: {type(config)}")
    print(f"配置内容键: {list(config.keys()) if hasattr(config, 'keys') else '无键'}")
    print(f"配置长度: {len(config) if isinstance(config, (list, tuple)) else '单元素'}")
    # 断点2 - 查看配置结构
    samples = []  #初始化结果列表

    
    # ==================== 断点3：创建基础模型组件前 ====================
    print("断点3：开始创建基础模型组件")
    print(f"预训练模型路径: {args.pretrained_model_path}")
    # 断点3 - 观察模型加载前的状态

    # 创建验证管道所需的基础组件
    tokenizer    = CLIPTokenizer.from_pretrained(args.pretrained_model_path, subfolder="tokenizer") #加载分词器：将文本转换为 token
    text_encoder = CLIPTextModel.from_pretrained(args.pretrained_model_path, subfolder="text_encoder").cuda()#加载文本编码器：将 token 转换为文本嵌入  
    vae          = AutoencoderKL.from_pretrained(args.pretrained_model_path, subfolder="vae").cuda()#加载 VAE：编码和解码图像 .cuda():将模型移动到 GPU

    # ==================== 断点4：基础模型组件创建后 ====================
    print("断点4：基础模型组件已创建")
    print(f"Tokenizer类型: {type(tokenizer)}")
    print(f"Text Encoder类型: {type(text_encoder)}")
    print(f"VAE类型: {type(vae)}")
    print(f"Text Encoder设备: {text_encoder.device}")
    print(f"VAE设备: {vae.device}")
    # 断点4 - 检查模型组件状态
    
    # 第二步：模型构建与加载
    sample_idx = 0  

    # 遍历配置中的每个模型设置
    for model_idx, model_config in enumerate(config):  #遍历配置文件中的所有模型配置
        # ==================== 断点5：处理每个模型配置开始 ====================
        print(f"\n断点5：开始处理第 {model_idx+1} 个模型配置")
        print(f"模型配置类型: {type(model_config)}")
        print(f"模型配置键: {list(model_config.keys())}")
        # 断点5 - 查看当前模型配置

        # 设置视频尺寸参数，使用配置值或默认值
        model_config.W = model_config.get("W", args.W)
        model_config.H = model_config.get("H", args.H)
        model_config.L = model_config.get("L", args.L)  #设置宽度、高度、视频长度（帧数）参数，优先使用配置文件中的值
 
        print(f"视频尺寸: W={model_config.W}, H={model_config.H}, L={model_config.L}")
        
        # ==================== 断点6：加载推理配置后 ====================
        #UNet 构建，加载推理配置文件，从 2D UNet 创建 3D UNet，集成运动模块
        inference_config = OmegaConf.load(model_config.get("inference_config", args.inference_config))
        print("断点6：推理配置已加载")
        print(f"推理配置类型: {type(inference_config)}")
        print(f"推理配置内容键: {list(inference_config.keys())}")
        
        #这里调用了animatediff/models/unet.py 重点：加载的是 SD v1.5 的 2D 权重，它通过配置强制将 2D 卷积层替换为了 InflatedConv3d（膨胀卷积）。
        # 此时的状态：UNet 是 3D 结构的，但它的“动作模块（Motion Module）”参数是随机初始化的，还没法用。
        # #断点6 - 查看推理配置
        unet = UNet3DConditionModel.from_pretrained_2d(args.pretrained_model_path, subfolder="unet", unet_additional_kwargs=OmegaConf.to_container(inference_config.unet_additional_kwargs)).cuda()

        
        # ==================== 断点7：UNet创建后 ====================
        print("断点7：UNet模型已创建")
        print(f"UNet类型: {type(unet)}")
        print(f"UNet设备: {unet.device}")
        
         # 断点7 - 检查UNet模型

        # 检查ControlNet配置
        print(f"ControlNet路径配置: {model_config.get('controlnet_path', '未设置')}")
        print(f"ControlNet路径为空? {model_config.get('controlnet_path', '') == ''}")
        
        # 加载 controlnet 模型,初始化
        controlnet = controlnet_images = None
        if model_config.get("controlnet_path", "") != "": #如果配置了 ControlNet，则加载 ControlNet 模型，处理控制图像（RGB 或草图）
            # ==================== 断点8：开始处理ControlNet ====================
            # 验证ControlNet配置完整性
            assert model_config.get("controlnet_images", "") != ""
            assert model_config.get("controlnet_config", "") != ""
            
            print(f"ControlNet路径: {model_config.controlnet_path}")
            print(f"ControlNet图像: {model_config.controlnet_images}")
            print(f"ControlNet配置: {model_config.controlnet_config}")
             # 断点8 - 查看ControlNet配置

            # 配置UNet参数
            unet.config.num_attention_heads = 8
            unet.config.projection_class_embeddings_input_dim = None
            #加载ControlNet配置并创建模型
            controlnet_config = OmegaConf.load(model_config.controlnet_config)
            controlnet = SparseControlNetModel.from_unet(unet, controlnet_additional_kwargs=controlnet_config.get("controlnet_additional_kwargs", {}))
            
            # ==================== 断点9：ControlNet模型创建后 ====================
            print("断点9：ControlNet模型已创建")
            print(f"ControlNet类型: {type(controlnet)}")
             # 断点9 - 检查ControlNet模型

            ## 下载并加载预训练权重
            auto_download(model_config.controlnet_path, is_dreambooth_lora=False)
            print(f"loading controlnet checkpoint from {model_config.controlnet_path} ...")
            controlnet_state_dict = torch.load(model_config.controlnet_path, map_location="cpu")

            # ==================== 断点10：ControlNet权重加载后 ====================
            print("断点10：ControlNet权重已加载")
            print(f"权重文件键: {list(controlnet_state_dict.keys())}")
            print(f"权重文件类型: {type(controlnet_state_dict)}")
            # 断点10 - 查看权重文件结构

            # 过滤和清理权重（移除位置编码和配置信息）
            controlnet_state_dict = torch.load(model_config.controlnet_path, map_location="cpu")
            controlnet_state_dict = controlnet_state_dict["controlnet"] if "controlnet" in controlnet_state_dict else controlnet_state_dict
            controlnet_state_dict = {name: param for name, param in controlnet_state_dict.items() if "pos_encoder.pe" not in name}
            controlnet_state_dict.pop("animatediff_config", "")

            print(f"处理后的权重键数量: {len(controlnet_state_dict.keys())}")
            print(f"前5个权重键: {list(controlnet_state_dict.keys())[:5]}")
            # 断点10.1 - 查看处理后的权重

            controlnet.load_state_dict(controlnet_state_dict)
            controlnet.cuda()

            # ==================== 断点11：ControlNet权重加载到模型后 ====================
            print("断点11：ControlNet权重已加载到模型")
            print(f"ControlNet设备: {controlnet.device}")
            # 断点11 - 检查加载后的ControlNet

            #从配置中获取控制图像的路径
            image_paths = model_config.controlnet_images
            if isinstance(image_paths, str): image_paths = [image_paths] #统一路径格式。如果只提供了单个图像路径（字符串），将其转换为列表形式，便于后续统一处理。
            
            
            #验证图像数量。确保控制图像的数量不超过视频的总帧数（model_config.L），避免图像数量超出视频长度
            assert len(image_paths) <= model_config.L

            # ==================== 断点12：控制图像路径处理完成 ====================
            print(f"断点12：控制图像路径处理完成，共 {len(image_paths)} 张图像")
            # 断点12 - 查看图像路径

            # 图像变换：调整尺寸并转换为Tensor
            image_transforms = transforms.Compose([
                transforms.RandomResizedCrop(
                    (model_config.H, model_config.W), (1.0, 1.0), 
                    ratio=(model_config.W/model_config.H, model_config.W/model_config.H)
                ),
                transforms.ToTensor(),
            ])

            print(f"图像变换配置: {image_transforms}")
            # 断点12.1 - 查看图像变换配置

            # 可选的归一化处理
            if model_config.get("normalize_condition_images", False):
                # 处理流程：RGB图像 → 灰度图 → 复制为3通道 → 最小-最大归一化
                def image_norm(image):
                    image = image.mean(dim=0, keepdim=True).repeat(3,1,1) # 转为单通道灰度图再复制为3通道
                    image -= image.min() # 最小值归零
                    image /= image.max() # 最大值归一化到[0,1]范围
                    return image
            else: image_norm = lambda x: x # 恒等函数，不做任何处理
            
            print(f"是否归一化: {model_config.get('normalize_condition_images', False)}")
            # 断点12.2 - 查看归一化设置

            # ==================== 断点13：开始加载和预处理控制图像 ====================
            print("断点13：开始加载和预处理控制图像")
            # 断点13 - 开始图像处理
            #图像加载和预处理
            controlnet_images = [image_norm(image_transforms(Image.open(path).convert("RGB"))) for path in image_paths]#加载图像并确保RGB格式，应用尺寸调整和Tensor转换，应用可选的归一化处理
            
            # ==================== 断点14：控制图像预处理完成 ====================
            print("断点14：控制图像预处理完成")
            print(f"控制图像数量: {len(controlnet_images)}")
            print(f"单个图像形状: {controlnet_images[0].shape if controlnet_images else '无图像'}")
            # 断点14 - 查看预处理后的图像

            #将处理后的控制图像保存为PNG文件，便于可视化检查预处理效果。
            os.makedirs(os.path.join(savedir, "control_images"), exist_ok=True)
            for i, image in enumerate(controlnet_images):
                Image.fromarray((255. * (image.numpy().transpose(1,2,0))).astype(np.uint8)).save(f"{savedir}/control_images/{i}.png")

            print(f"控制图像已保存到: {savedir}/control_images/")
            # 断点14.1 - 检查图像保存

            # 将图像列表转为张量并调整维度
            controlnet_images = torch.stack(controlnet_images).unsqueeze(0).cuda()  #将图像列表转为张量 [f, c, h, w] ，添加batch维度 [1, f, c, h, w]
            controlnet_images = rearrange(controlnet_images, "b f c h w -> b c f h w") #调整维度顺序为 [batch, channel, frame, height, width]

            # ==================== 断点15：控制图像张量化完成 ====================
            print("断点15：控制图像张量化完成")
            print(f"控制图像张量形状: {controlnet_images.shape}")
            # 断点15 - 查看张量化后的图像
            
            # 如果使用简化条件嵌入，通过VAE编码到潜在空间
            if controlnet.use_simplified_condition_embedding:
                num_controlnet_images = controlnet_images.shape[2]  # 保存帧数
                controlnet_images = rearrange(controlnet_images, "b c f h w -> (b f) c h w") # 合并batch和frame
                controlnet_images = vae.encode(controlnet_images * 2. - 1.).latent_dist.sample() * 0.18215 # VAE编码到潜在空间
                controlnet_images = rearrange(controlnet_images, "(b f) c h w -> b c f h w", f=num_controlnet_images) # 恢复原始维度
                 # ==================== 断点16：控制图像VAE编码完成 ====================
                print("断点16：控制图像VAE编码完成")
                print(f"编码后形状: {controlnet_images.shape}")
                # 断点16 - 查看编码后的图像

        # ==================== 断点17：设置xformers前 ====================
        print("断点17：检查xformers设置")
        print(f"xformers是否可用: {is_xformers_available()}")
        print(f"是否禁用xformers: {args.without_xformers}")
        # 断点17 - 查看xformers状态

        # set xformers 如果可用且未禁用，启用 xformers 内存高效注意力
        if is_xformers_available() and (not args.without_xformers):
            unet.enable_xformers_memory_efficient_attention()
            if controlnet is not None: controlnet.enable_xformers_memory_efficient_attention()
        
        # ==================== 断点18：创建动画管道前(生产线搭建) ====================
        print("断点18：准备创建动画管道")
        print(f"ControlNet存在: {controlnet is not None}")
        print(f"ControlNet图像存在: {controlnet_images is not None}")
        # 断点18 - 查看管道创建前的状态
        
        #管道组装，组装完整的动画生成管道，包含 VAE、文本编码器、UNet、ControlNet、调度器
        pipeline = AnimationPipeline(
            vae=vae, text_encoder=text_encoder, tokenizer=tokenizer, unet=unet,
            controlnet=controlnet,
            scheduler=DDIMScheduler(**OmegaConf.to_container(inference_config.noise_scheduler_kwargs)),
        ).to("cuda")
        

        # ==================== 断点19：动画管道创建后 ====================
        print("断点19：动画管道已创建")
        print(f"Pipeline类型: {type(pipeline)}")
        print(f"Pipeline设备: {pipeline.device}")
        # 断点19 - 检查创建的管道

        #权重加载，注入灵魂  调用文件：animatediff/utils/util.py
        #这是 AnimateDiff 论文的核心实现点：模块化插入。
        pipeline = load_weights(
            pipeline,
            # motion module ，加载运动模块权重
            motion_module_path         = model_config.get("motion_module", ""),
            motion_module_lora_configs = model_config.get("motion_module_lora_configs", []),
            # domain adapter
            adapter_lora_path          = model_config.get("adapter_lora_path", ""),
            adapter_lora_scale         = model_config.get("adapter_lora_scale", 1.0),
            # image layers ，加载 DreamBooth 个性化模型 ， 加载 LoRA 适配器权重
            dreambooth_model_path      = model_config.get("dreambooth_path", ""),
            lora_model_path            = model_config.get("lora_model_path", ""),
            lora_alpha                 = model_config.get("lora_alpha", 0.8),
        ).to("cuda")
        
        # ==================== 断点20：权重加载后 ====================
        print("断点20：权重已加载到管道")
        print(f"运动模块路径: {model_config.get('motion_module', '未设置')}")
        print(f"LoRA模型路径: {model_config.get('lora_model_path', '未设置')}")
        # 断点20 - 检查权重加载后的管道

        # 第三步：预处理与设置
        # 处理多个提示词
        # 准备提示词和参数
        prompts      = model_config.prompt
        n_prompts    = list(model_config.n_prompt) * len(prompts) if len(model_config.n_prompt) == 1 else model_config.n_prompt
        #处理负向提示词
        random_seeds = model_config.get("seed", [-1])
        #处理随机种子，支持单个种子或多个种子
        random_seeds = [random_seeds] if isinstance(random_seeds, int) else list(random_seeds)
        random_seeds = random_seeds * len(prompts) if len(random_seeds) == 1 else random_seeds
        
        #第四步：推理生成视频
        #生成循环，遍历每个提示词和对应的种子，为每个组合生成动画
        config[model_idx].random_seed = []

        
        # ==================== 新插入代码结束 ====================

        # ==================== 断点21：开始处理每个提示词 ====================
        print("断点21：开始处理提示词")
        print(f"提示词数量: {len(prompts)}")
        print(f"前3个提示词: {prompts[:3] if len(prompts) > 3 else prompts}")
        print(f"负面提示词数量: {len(n_prompts)}")
        print(f"随机种子: {random_seeds}")
        # 断点21 - 查看提示词相关信息

        for prompt_idx, (prompt, n_prompt, random_seed) in enumerate(zip(prompts, n_prompts, random_seeds)):
            
            # ==================== 断点22：开始处理单个提示词 ====================
            print(f"\n断点22：开始处理第 {prompt_idx+1} 个提示词")
            print(f"提示词: {prompt}")
            print(f"负面提示词: {n_prompt}")
            print(f"随机种子: {random_seed}")
            # 断点22 - 查看单个提示词信息

            # manually set random seed for reproduction
            if random_seed != -1: torch.manual_seed(random_seed)  #设置随机种子确保结果可重现
            else: torch.seed()
            config[model_idx].random_seed.append(torch.initial_seed()) #记录实际使用的种子

            print(f"\nProcessing prompt {prompt_idx+1}/{len(prompts)}: {prompt}")
            print(f"Current seed: {torch.initial_seed()}")

            # ================= [隐写注入 Start] =================
            print(f">>> [Stego] Generating secret noise...")

            # (A) 统一秘密信息
            secret_text = args.secret_text if hasattr(args, 'secret_text') and args.secret_text else "This is a secret message hidden in video!"
 
            # (B) 初始化处理器
            stego_processor = StegoProcessor(
                height=model_config.H, 
                width=model_config.W, 
                video_length=model_config.L,
                channels=4,                    # 新增
                downsample_factor=8,           # 新增
                key=args.key
            )
            
            # (C) 生成噪声
            msg_bits = stego_processor.str_to_bits(secret_text)
            stego_latents = stego_processor.prepare_secret_noise(
                msg_bits, 
                device="cuda", 
                dtype=torch.float32, # 保持高精度
                target_bpf=args.target_bpf
            )
            print(f">>> [Stego] Injected: '{secret_text}'")

            # (D) 保存秘密信息到文件
            secret_save_path = f"{savedir}/secret.txt"
            with open(secret_save_path, 'w') as f:
                f.write(secret_text)
            print(f">>> [Stego] Secret saved to: {secret_save_path}")

            config_save_path = f"{savedir}/stego_config.txt"
            with open(config_save_path, 'w') as f:
                f.write(f"key={args.key}\n")  # <--- [修改] 动态记录生成的密钥
                # [修改] 这里的 msg_len 应该是实际嵌入的长度 (target_bpf * frames)
                real_msg_len = int(args.target_bpf * model_config.L)
                f.write(f"msg_len={real_msg_len}\n") 
                f.write(f"secret={secret_text}\n")
                f.write(f"bpf={args.target_bpf}\n") # 记录 BPF 以便查阅
            print(f">>> [Stego] 配置保存到: {config_save_path}")
            # ================= [隐写注入 End] =================


            #传递所有生成参数，返回生成的视频张量
            #将 Prompt ("1girl, dancing...") 和视频长度 (L=16) 传入 Pipeline。
            #连接点：这是 animate.py 将控制权移交给 pipeline_animation.py 的精确时刻。
            #
            pipeline.unet = pipeline.unet.float()
            pipeline.vae = pipeline.vae.float()
            if controlnet: pipeline.controlnet = pipeline.controlnet.float()
            #
            sample = pipeline(
                prompt,
                negative_prompt     = n_prompt,
                num_inference_steps = model_config.steps,
                guidance_scale      = model_config.guidance_scale,
                width               = model_config.W,
                height              = model_config.H,
                video_length        = model_config.L,

                controlnet_images = controlnet_images,
                controlnet_image_index = model_config.get("controlnet_image_indexs", [0]),
              
                # [关键修改] 这里一定要把 stego_latents 传进去！
                latents = stego_latents,

                output_type = "tensor",
            ).videos

            #保存单个样本
            samples.append(sample)

            # ==================== 断点24：视频生成后 ====================
            print("断点24：视频已生成")
            print(f"生成样本类型: {type(sample)}")
            print(f"生成样本形状: {sample.shape if hasattr(sample, 'shape') else '无形状'}")
            print(f"生成样本设备: {sample.device if hasattr(sample, 'device') else '无设备'}")
            # 断点24 - 查看生成的视频样本

            #使用提示词前10个单词作为文件名
            prompt = "-".join((prompt.replace("/", "").split(" ")[:10]))

            # ==================== 断点25：保存视频前 ====================
            print("断点25：准备保存视频")
            
            # 断点25 - 查看保存前的状态

            # 保存单个视频
            save_videos_grid(sample, f"{savedir}/sample/{sample_idx}-{prompt}.gif")  #调用 util.py 的 save_videos_grid，util调用 imageio.mimsave，将这 16 帧图片合成一个 .gif 文件，存入硬盘
            print(f"save to {savedir}/sample/{prompt}.gif")
            #递增样本索引
            sample_idx += 1

            # ==================== 断点26：单个视频保存后 ====================
            print("断点26：单个视频已保存")
            # 断点26 - 确认保存完成

    
    
    # ==================== 断点27：所有视频生成完成后 ====================
    print("\n断点27：所有视频生成完成")
    print(f"总样本数量: {len(samples)}")
    print(f"所有样本类型: {type(samples)}")
    # 断点27 - 查看所有生成的样本

    # 第五步：保存生成的视频
    #保存样本网格
    samples = torch.concat(samples)
    save_videos_grid(samples, f"{savedir}/sample.gif", n_rows=4)

    # ==================== 断点28：最终保存前 ====================
    print("断点28：准备保存最终结果和配置")
    print(f"合并后样本形状: {samples.shape}")
    # 断点28 - 查看最终保存前的状态

    #保存完整配置
    OmegaConf.save(config, f"{savedir}/config.yaml")

    # ==================== 断点29：程序结束前 ====================
    print("断点29：程序即将结束")
    print(f"结果保存目录: {savedir}")
    print(f"配置已保存: {savedir}/config.yaml")
    # 断点29 - 最终检查

# 当你运行命令时，Python解释器首先执行这个文件
if __name__ == "__main__": 
    # 第一步：命令行参数解析
    parser = argparse.ArgumentParser()Parser = argparse.ArgumentParser（）
    parser.add_argument("--pretrained-model-path", type=str, default="runwayml/stable-diffusion-v1-5")   #用了HuggingFace模型云端 ID 而不是本地路径
    parser.add_argument("--inference-config",      type=str, default="configs/inference/inference-v1.yaml") #默认 inference-v1.yaml配置   （采样器、动态图参数）负责怎么采样，怎么生成多帧动画，加载什么 Motion Module等等
    parser.add_argument("--config",                type=str, required=True)# 接收命令行的配置信息，比如：configs/prompts/1_animate/1_3_animate_ToonYou.yaml
    
    parser.add_argument("--secret-text", type=str, default="", help="Secret message to embed")
    parser.add_argument("--key", type=int, default=42, help="共享密钥 (伪随机置乱种子)")

    parser.add_argument("--L", type=int, default=16 )  #视频长度/帧数
    parser.add_argument("--W", type=int, default=512)  #图像宽度
    parser.add_argument("--H", type=int, default=512)  #图像长度
    parser.add_argument("--target-bpf", type=int, default=96, choices=[96, 192, 384],help="Target Bits Per Frame (Align with paper: 96, 192, 384)")
 
    # 性能优化
    parser.add_argument("--without-xformers", action="store_true")
     # 是否禁用xformers优化（默认启用）
    args = parser.parse_args()

    # ==================== 断点0：主函数调用前 ====================
    print("断点0：主函数即将被调用")
    print(f"命令行参数: {args}")
    print(f"配置文件: {args.config}")
    print(f"宽高L: {args.L}, W: {args.W}, H: {args.H}")
    #查看参数解析后的状态
    
    main(args) # 调用main函数，传入解析后的参数对象
