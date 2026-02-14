import argparse
import torch
import numpy as np
import imageio
import os
from omegaconf import OmegaConf
from diffusers import AutoencoderKL, DDIMScheduler
from transformers import CLIPTextModel, CLIPTokenizer, CLIPProcessor, CLIPModel
from animatediff.models.unet import UNet3DConditionModel
from animatediff.utils.util import load_weights
from animatediff.utils.stego import StegoProcessor
from einops import rearrange
from tqdm import tqdm
from diffusers.utils.import_utils import is_xformers_available

# ==================== 新增: 修正的CLIP评估函数 ====================
def simple_clip_evaluation(frames, prompt, reference_image=None, device="cuda"):
    """
    修正的CLIP评估函数，使用正确的余弦相似度计算
    返回: 文本对齐度, 域相似性(可选), 视频一致性
    """
    try:
        # 加载CLIP模型
        clip_model = CLIPModel.from_pretrained("openai/clip-vit-base-patch32").to(device)
        processor = CLIPProcessor.from_pretrained("openai/clip-vit-base-patch32")
        clip_model.eval()
        
        results = {}
        
        with torch.no_grad():
            # 将视频帧转换为PIL图像
            from PIL import Image
            pil_frames = [Image.fromarray(frame) for frame in frames]
            
            # 1. 计算文本对齐度 - 修正：使用余弦相似度而非logits
            if prompt:
                # 提取文本特征
                text_inputs = processor(text=[prompt], return_tensors="pt", padding=True).to(device)
                text_features = clip_model.get_text_features(**text_inputs)
                text_features = text_features / text_features.norm(dim=-1, keepdim=True)
                
                # 计算每帧的相似度
                similarities = []
                for frame_img in pil_frames:
                    # 提取图像特征
                    image_inputs = processor(images=frame_img, return_tensors="pt").to(device)
                    image_features = clip_model.get_image_features(**image_inputs)
                    image_features = image_features / image_features.norm(dim=-1, keepdim=True)
                    
                    # 计算余弦相似度
                    sim = (image_features @ text_features.T).item()
                    similarities.append(sim)
                
                text_alignment = float(np.mean(similarities))
                results['text_alignment'] = text_alignment
                print(f"文本对齐度: {text_alignment:.4f}")
            
            # 2. 计算视频一致性 (帧间相似度)
            if len(pil_frames) > 1:
                consistency_scores = []
                # 计算相邻帧的CLIP相似度
                for i in range(len(pil_frames) - 1):
                    frame1 = pil_frames[i]
                    frame2 = pil_frames[i + 1]
                    
                    inputs = processor(
                        images=[frame1, frame2],
                        return_tensors="pt"
                    ).to(device)
                    
                    with torch.no_grad():
                        features = clip_model.get_image_features(inputs.pixel_values)
                        features = features / features.norm(dim=-1, keepdim=True)
                        sim = (features[0] @ features[1].T).item()
                        consistency_scores.append(sim)
                
                video_consistency = float(np.mean(consistency_scores))
                results['video_consistency'] = video_consistency
                print(f"视频一致性: {video_consistency:.4f}")
            
            # 3. 计算域相似性 (如果有参考图像)
            if reference_image is not None and os.path.exists(reference_image):
                ref_img = Image.open(reference_image).convert("RGB")
                domain_scores = []
                
                # 提取参考图像特征
                ref_inputs = processor(images=ref_img, return_tensors="pt").to(device)
                ref_features = clip_model.get_image_features(ref_inputs.pixel_values)
                ref_features = ref_features / ref_features.norm(dim=-1, keepdim=True)
                
                for frame_img in pil_frames:
                    # 提取帧图像特征
                    frame_inputs = processor(images=frame_img, return_tensors="pt").to(device)
                    frame_features = clip_model.get_image_features(frame_inputs.pixel_values)
                    frame_features = frame_features / frame_features.norm(dim=-1, keepdim=True)
                    
                    # 计算余弦相似度
                    sim = (frame_features @ ref_features.T).item()
                    domain_scores.append(sim)
                
                domain_similarity = float(np.mean(domain_scores))
                results['domain_similarity'] = domain_similarity
                print(f"域相似性: {domain_similarity:.4f}")
        
        return results
        
    except Exception as e:
        print(f"CLIP评估出错: {e}")
        return {}

# ==================== 新增: 与论文结果比对函数 ====================
def compare_with_paper(evaluation_results, embed_capacity=96):
    """
    与论文中的基准结果进行比对
    论文结果参考 (Table 1):
    - 文本对齐度: ~0.2918
    - 域相似性: ~0.7655
    - 视频一致性: ~0.9312
    """
    paper_baseline = {
        96: {  # 96 bpf
            'text_alignment': 0.2918,
            'domain_similarity': 0.7655,
            'video_consistency': 0.9312,
        },
        192: {  # 192 bpf
            'text_alignment': 0.2918,
            'video_consistency': 0.9312,
        },
        384: {  # 384 bpf
            'text_alignment': 0.2918,
            'video_consistency': 0.9312,
        }
    }
    
    if embed_capacity not in paper_baseline:
        print(f"警告: 没有嵌密容量 {embed_capacity} bpf 的论文基准数据")
        return
    
    baseline = paper_baseline[embed_capacity]
    
    print("\n" + "="*50)
    print("与论文结果比对")
    print("="*50)
    
    comparison_data = []
    for metric, paper_value in baseline.items():
        if metric in evaluation_results:
            our_value = evaluation_results[metric]
            diff = our_value - paper_value
            diff_pct = (diff / paper_value) * 100 if paper_value != 0 else 0
            
            if diff > 0.01:  # 优于论文超过1%
                status = "✅ 显著优于论文"
            elif diff > 0:
                status = "✅ 优于论文"
            elif diff < -0.01:  # 低于论文超过1%
                status = "⚠️ 显著低于论文"
            elif diff < 0:
                status = "⚠️ 低于论文"
            else:
                status = "➖ 与论文持平"
            
            print(f"{metric}: 论文={paper_value:.4f}, 我们的={our_value:.4f}, {status} ({diff_pct:+.2f}%)")
            comparison_data.append({
                'metric': metric,
                'paper': paper_value,
                'ours': our_value,
                'diff': diff,
                'diff_pct': diff_pct,
                'status': status
            })
    
    return comparison_data

# ==================== 新增: 读取视频帧函数 ====================
def load_video_frames(video_path):
    """读取视频并返回帧数组"""
    print(f">>> 正在读取视频: {video_path}")
    try:
        reader = imageio.get_reader(video_path)
        frames = []
        for frame in reader:
            # 确保为RGB格式
            if frame.ndim == 3 and frame.shape[-1] == 4:
                frame = frame[..., :3]  # 移除alpha通道
            frames.append(frame)
        return np.array(frames)
    except Exception as e:
        print(f"读取视频失败: {e}")
        return None

def load_video_latents(video_path, vae, device="cuda", dtype=torch.float16):
    print(f"Loading video: {video_path}")
    reader = imageio.get_reader(video_path)
    frames = []
    for frame in reader:
        if frame.ndim == 3 and frame.shape[-1] == 4:
            frame = frame[..., :3]
        frames.append(frame)
    frames = np.array(frames)
    
    # 归一化到 [-1, 1]
    video_tensor = torch.tensor(frames).float() / 127.5 - 1.0
    video_tensor = rearrange(video_tensor, "f h w c -> 1 c f h w")
    video_tensor = video_tensor.to(device=device, dtype=dtype)
    
    b, c, f, h, w = video_tensor.shape
    video_tensor_reshaped = rearrange(video_tensor, "b c f h w -> (b f) c h w")
    
    with torch.no_grad():
        latents = vae.encode(video_tensor_reshaped).latent_dist.sample()
        latents = latents * 0.18215
        
    latents = rearrange(latents, "(b f) c h w -> b c f h w", b=b, f=f)
    return latents

@torch.no_grad()
def ddim_inversion_advanced(unet, scheduler, latents, num_steps, prompt_embeds, device, weight_dtype):
    """
    高级DDIM逆向：结合动量优化
    """
    scheduler_new = DDIMScheduler.from_config(scheduler.config)
    scheduler_new.set_timesteps(num_steps, device=device)
    timesteps = reversed(scheduler_new.timesteps)
    
    # 关键：状态变量必须是 float32
    current_latents = latents.clone().float()
    
    # Prompt Embedding 转为模型精度
    prompt_embeds = prompt_embeds.to(dtype=weight_dtype)
    
    print(f"Running Advanced DDIM Inversion ({num_steps} steps)...")
    
    # 使用动量优化
    momentum = 0.9
    velocity = torch.zeros_like(current_latents)
    
    for i, t in enumerate(tqdm(timesteps)):
        # 临时转为 float16 输入模型
        latent_input = current_latents.to(dtype=weight_dtype)
        
        # 模型预测
        noise_pred = unet(latent_input, t, encoder_hidden_states=prompt_embeds).sample
        
        # 立即转回 float32 进行数学更新
        noise_pred = noise_pred.float()
        
        # DDIM 逆向公式
        alpha_prod_t = scheduler_new.alphas_cumprod[t]
        beta_prod_t = 1 - alpha_prod_t
        
        pred_original_sample = (current_latents - beta_prod_t ** 0.5 * noise_pred) / alpha_prod_t ** 0.5
        
        # 计算前一时间步
        if i < len(timesteps) - 1:
            prev_t = timesteps[i + 1]
            alpha_prod_t_prev = scheduler_new.alphas_cumprod[prev_t]
        else:
            alpha_prod_t_prev = scheduler_new.alphas_cumprod[0]
            
        # 应用动量优化
        new_latents = alpha_prod_t_prev ** 0.5 * pred_original_sample + (1 - alpha_prod_t_prev) ** 0.5 * noise_pred
        
        # 动量更新
        velocity = momentum * velocity + (1 - momentum) * (new_latents - current_latents)
        current_latents = current_latents + velocity
        
    return current_latents

def main(args):
    device = "cuda"
    weight_dtype = torch.float16
    
    config = OmegaConf.load(args.config)
    inference_config = OmegaConf.load(args.inference_config)
    
    # 获取视频序号
    video_name = os.path.basename(args.video_path)
    video_idx = -1
    if '-' in video_name:
        try:
            idx_part = video_name.split('-')[0]
            video_idx = int(idx_part)
            print(f"检测到视频序号: {video_idx}")
        except ValueError:
            print(f"无法从文件名提取序号: {video_name}")
    
    # 获取正确的prompt
    if args.prompt == "" and video_idx >= 0:
        # 从配置文件获取prompt
        all_prompts = []
        for model_config in config:
            if hasattr(model_config, 'prompt'):
                prompts = model_config.prompt
                if isinstance(prompts, str):
                    all_prompts.append(prompts)
                elif OmegaConf.is_list(prompts) or isinstance(prompts, list):
                    for p in prompts:
                        all_prompts.append(str(p))
        
        if 0 <= video_idx < len(all_prompts):
            args.prompt = all_prompts[video_idx]
            print(f"从配置文件获取Prompt[{video_idx}]: '{args.prompt}'")
        else:
            print("⚠️ 警告: 无法从配置文件获取正确的Prompt")
            args.prompt = ""
    elif args.prompt:
        print(f"使用用户指定的Prompt: '{args.prompt}'")
    else:
        print("⚠️ 警告: 未提供 Prompt！提取准确率可能会极低。")
        args.prompt = ""
    
    # 加载模型
    tokenizer = CLIPTokenizer.from_pretrained(args.pretrained_model_path, subfolder="tokenizer")
    text_encoder = CLIPTextModel.from_pretrained(args.pretrained_model_path, subfolder="text_encoder").to(device, weight_dtype)
    vae = AutoencoderKL.from_pretrained(args.pretrained_model_path, subfolder="vae").to(device, weight_dtype)
    
    unet = UNet3DConditionModel.from_pretrained_2d(
        args.pretrained_model_path, 
        subfolder="unet", 
        unet_additional_kwargs=OmegaConf.to_container(inference_config.unet_additional_kwargs)
    ).to(device, weight_dtype)
    
    if is_xformers_available():
        print(">>> Enabling xFormers memory efficient attention")
        unet.enable_xformers_memory_efficient_attention()

    # 加载运动模块等权重
    if OmegaConf.is_list(config):
        first_config = config[0]
        motion_module = first_config.get("motion_module", "")
        motion_module_lora_configs = first_config.get("motion_module_lora_configs", [])
    else:
        motion_module = config.get("motion_module", "")
        motion_module_lora_configs = config.get("motion_module_lora_configs", [])
    
    print(f"使用motion_module: {motion_module}")
    
    pipeline_wrapper = type('Pipeline', (object,), {'unet': unet, 'vae': vae, 'text_encoder': text_encoder})
    pipeline_wrapper = load_weights(
        pipeline_wrapper,
        motion_module_path=motion_module,
        motion_module_lora_configs=motion_module_lora_configs
    )
    unet = pipeline_wrapper.unet
    
    scheduler = DDIMScheduler(**OmegaConf.to_container(inference_config.noise_scheduler_kwargs))
    
    # 读取视频
    latents = load_video_latents(args.video_path, vae, device, weight_dtype)
    
    # 编码 Prompt
    print(f"最终使用的Prompt: '{args.prompt}'")
    
    text_inputs = tokenizer(
        args.prompt, 
        padding="max_length", 
        max_length=tokenizer.model_max_length, 
        truncation=True, 
        return_tensors="pt"
    )
    text_embeddings = text_encoder(text_inputs.input_ids.to(device))[0]
    
    # 自适应DDIM逆向
    if video_idx < 2:
        steps = 50
        print(f"第一组视频（序号{video_idx}），使用50步DDIM反转")
    else:
        steps = 100
        print(f"第二组视频（序号{video_idx}），使用100步DDIM反转")
    
    recovered_noise = ddim_inversion_advanced(unet, scheduler, latents, steps, text_embeddings, device, weight_dtype)
    
    print(f"DDIM反转完成，recovered_noise类型: {recovered_noise.dtype}")
    if recovered_noise.dtype != torch.float32:
        recovered_noise = recovered_noise.float()
    
    # 集成提取信息
    frames = recovered_noise.shape[2]
    h_latent = recovered_noise.shape[3]
    w_latent = recovered_noise.shape[4]
    height = h_latent * 8
    width = w_latent * 8
    
    print(f"Detected Latent Shape: {recovered_noise.shape}")
    print(f"Auto-configured StegoProcessor: H={height}, W={width}, L={frames}")
    
    # 创建StegoProcessor，使用与发送方相同的密钥
    stego_processor = StegoProcessor(
        height=height, 
        width=width,  
        video_length=frames,
        channels=4,
        downsample_factor=8,
        key=args.key  # 使用共享密钥
    )

    # 1. 确定目标 BPF (优先级: 命令行 > 配置文件 > 默认值96)
    target_bpf = args.target_bpf 
    
    video_dir = os.path.dirname(args.video_path)
    config_file = os.path.join(video_dir, "stego_config.txt")
    
    # 尝试从 stego_config.txt 读取 bpf (生成时记录的)
    if target_bpf == 0 and os.path.exists(config_file):
        with open(config_file, 'r') as f:
            for line in f:
                if line.startswith("bpf="): 
                    target_bpf = int(float(line.split("=")[1].strip()))
    
    if target_bpf == 0: target_bpf = 96 # 默认对齐论文基准 96
    
    print(f"\n>>> [Config] 目标 BPF: {target_bpf} (论文对齐模式)")
    
    # 2. 确定用户实际消息长度 (用于最后截取)
    user_msg_len = args.msg_len
    if user_msg_len == 0 and os.path.exists(config_file):
        with open(config_file, 'r') as f:
            for line in f:
                if line.startswith("msg_len="): # 注意：这里读的是生成时记录的长度
                    # 如果生成时记录的是填充后的长度，这里可能会偏大，但没关系，截取时以最小为准
                    pass 
                if line.startswith("secret_len="): # 假设我们在animate里存了真实长度
                    user_msg_len = int(line.split("=")[1].strip())

    if user_msg_len == 0: user_msg_len = 224 # 如果都没找到，默认回退到224
    print(f">>> [Config] 有效消息长度: {user_msg_len} bits")

    # 3. 计算底层物理填充长度 (Extract Length)
    # 逻辑：论文中的 96 bpf 意味着 16 帧视频里总共填满了 96 * 16 = 1536 bits
    # 我们必须告诉提取器去提取这 1536 bits，而不是只提取 224 bits，否则投票会对不齐
    full_extract_len = int(target_bpf * frames)
    
    print(f">>> [Recover] 正在提取底层全量数据 (Length: {full_extract_len} bits)...")
    
    # 使用 full_extract_len 进行提取，这样 Repeats 计算才是对的
    # (Total_Capacity / 1536) 这是一个整数，不会错位
    recovered_payload = stego_processor.recover_message(recovered_noise, full_extract_len,actual_msg_len=user_msg_len)
    
    # 4. 截取有效信息
    # 因为生成时是循环填充的 (224, 224, 224, ...)，所以前 224 位不仅是完整的，而且是抗干扰最强的
    # 如果提取出的长度比用户需要的长，就截取；否则就全取
    if user_msg_len > 0 and user_msg_len <= len(recovered_payload):
        recovered_bits = recovered_payload[:user_msg_len]
        print(f">>> [Post-Process] 已从 {len(recovered_payload)} bits 中截取前 {user_msg_len} bits")
    else:
        recovered_bits = recovered_payload
    
    # 转换为文本
    recovered_text = StegoProcessor.bits_to_str(recovered_bits)
    
    print("\n" + "="*50)
    print(f"提取结果: {recovered_text}")
    print(f"提取比特数: {len(recovered_bits)}")
    
    # 保存结果到文件
    video_dir = os.path.dirname(args.video_path)
    output_file = os.path.join(video_dir, "extracted_secret.txt")
    with open(output_file, 'w') as f:
        f.write(f"提取结果: {recovered_text}\n")
        f.write(f"使用长度: {args.msg_len} bits\n")
    print(f"提取结果已保存到: {output_file}")
    
    # 如果存在秘密信息文件，用于验证（仅用于测试）
    secret_file_path = os.path.join(video_dir, "../secret.txt")
    if os.path.exists(secret_file_path):
        with open(secret_file_path, 'r') as f:
            original_secret = f.read().strip()
        
        print(f"找到验证文件，计算准确率...")
        original_bits = np.array([int(b) for b in StegoProcessor.str_to_bits(original_secret)])
        
        # 确保长度匹配
        min_len = min(len(original_bits), len(recovered_bits))
        if min_len > 0:
            correct = (original_bits[:min_len] == recovered_bits[:min_len]).sum()
            acc = correct / min_len
            print(f"原始秘密信息: {original_secret}")
            print(f"提取准确率: {acc * 100:.2f}% ({correct}/{min_len})")
    
    print("="*50)
    
    # ==================== 新增: 视频质量评估 (可选) ====================
    if args.eval_quality:
        print("\n" + "="*50)
        print("开始视频质量评估 (CLIP指标)")
        print("="*50)
        
        # 读取视频帧
        frames = load_video_frames(args.video_path)
        if frames is not None:
            # 查找参考图像
            reference_image = None
            # 尝试查找参考图像
            potential_ref_images = [
                os.path.join(video_dir, "control_images/0.png"),
                os.path.join(video_dir, "../control_images/0.png"),
                os.path.join(os.path.dirname(video_dir), "control_images/0.png")
            ]
            
            for ref_path in potential_ref_images:
                if os.path.exists(ref_path):
                    reference_image = ref_path
                    print(f"找到参考图像: {reference_image}")
                    break
            
            # 执行CLIP评估
            evaluation_results = simple_clip_evaluation(
                frames=frames,
                prompt=args.prompt,
                reference_image=reference_image,
                device=device
            )
            
            # 与论文结果比对
            if evaluation_results: # 只要有评估结果就对比
                # [修正] 直接显示真实的物理容量 (96)，而不是用户截取的长度 (14)
                print(f"\n当前物理嵌密容量: {target_bpf} bpf (论文对齐)")
                
                # 使用 target_bpf 作为基准去查表
                embed_capacity = target_bpf
                
                # 安全检查：如果没有对应基准，默认用 96 对比
                if embed_capacity not in [96, 192, 384]:
                    embed_capacity = 96
                
                print(f"使用论文基准容量: {embed_capacity} bpf 进行比对")
                
                # 与论文结果比对
                comparison_data = compare_with_paper(evaluation_results, embed_capacity=embed_capacity)
                
                # 保存评估结果
                eval_output_file = os.path.join(video_dir, "quality_evaluation.txt")
                with open(eval_output_file, 'w') as f:
                    f.write("视频质量评估结果\n")
                    f.write("="*50 + "\n")
                    f.write(f"视频文件: {args.video_path}\n")
                    f.write(f"Prompt: {args.prompt}\n")
                    f.write(f"帧数: {frames.shape[0]}\n")
                    f.write(f"实际嵌密容量: {target_bpf} bpf\n") # 修正这里
                    f.write(f"比对基准容量: {embed_capacity} bpf\n\n")
                    
                    f.write("评估指标:\n")
                    for metric, value in evaluation_results.items():
                        f.write(f"  {metric}: {value:.4f}\n")
                    
                    if comparison_data:
                        f.write("\n与论文结果比对:\n")
                        for item in comparison_data:
                            f.write(f"  {item['metric']}:\n")
                            f.write(f"    论文基准: {item['paper']:.4f}\n")
                            f.write(f"    我们的结果: {item['ours']:.4f}\n")
                            f.write(f"    差异: {item['diff']:+.4f} ({item['diff_pct']:+.2f}%)\n")
                            f.write(f"    状态: {item['status']}\n")
                
                print(f"\n评估结果已保存到: {eval_output_file}")
            else:
                print("评估结果为空或无法计算嵌密容量")
        else:
            print("无法读取视频帧，跳过质量评估")
    
    print("\n" + "="*50)
    print("程序执行完成")
    print("="*50)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=str, required=True)
    parser.add_argument("--inference-config", type=str, default="configs/inference/inference-v1.yaml")
    parser.add_argument("--pretrained-model-path", type=str, default="runwayml/stable-diffusion-v1-5")
    parser.add_argument("--video_path", type=str, required=True)
    parser.add_argument("--prompt", type=str, default="")
    
    # 新增: 隐写相关参数
    parser.add_argument("--key", type=int, default=42, help="共享密钥（必须与发送方一致）")
    parser.add_argument("--msg-len", type=int, default=0,help="秘密信息比特长度（如果不提供，会尝试自动检测）")
    parser.add_argument("--target-bpf", type=int, default=0,help="论文对齐参数：每帧嵌入比特数 (默认96, 可选192, 384)")

    # 新增: 质量评估参数
    parser.add_argument("--eval-quality", action="store_true",help="启用视频质量评估（计算CLIP分数）")
    
    # 原有参数
    parser.add_argument("--L", type=int, default=16)
    parser.add_argument("--W", type=int, default=512)
    parser.add_argument("--H", type=int, default=512)
    
    
    args = parser.parse_args()
    main(args)