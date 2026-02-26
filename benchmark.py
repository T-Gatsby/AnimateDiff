import os
import csv
import subprocess
import re
import numpy as np
import argparse
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
from video_attacks import VideoAttacker

# ================= 工具函数：计算比特误码率 (BER) =================
def str_to_bits(s):
    """将字符串转换为 0/1 比特列表，用于科学计算 BER"""
    result = []
    for c in s:
        # 将字符转为8位二进制
        bits = bin(ord(c))[2:].zfill(8)
        result.extend([int(b) for b in bits])
    return result

def calculate_metrics(secret_gt, extracted_msg):
    """
    计算准确率 (Accuracy) 和 误码率 (Bit Error Rate)
    这是论文 Table 3 和 Figure 4 必须的数据
    """
    # 1. 如果提取为空或失败
    if not extracted_msg:
        return 0.0, 1.0 # Acc=0, BER=100%

    # 2. 转为比特流进行科学比对
    bits_gt = str_to_bits(secret_gt)
    bits_ex = str_to_bits(extracted_msg)

    # 3. 对齐长度 (截断或补零)
    min_len = min(len(bits_gt), len(bits_ex))
    if min_len == 0:
        return 0.0, 1.0
        
    # 只比较重叠部分（论文通常只计算有效载荷的误码率）
    matches = sum([1 for i in range(min_len) if bits_gt[i] == bits_ex[i]])
    
    accuracy = matches / len(bits_gt) # 基于原始长度计算准确率
    ber = 1.0 - accuracy
    
    return accuracy, ber

# ================= 核心逻辑：黑盒调用 extract.py =================
def run_extraction_blackbox(video_path, prompt, msg_len, config_path, key, target_bpf):
    """
    通过命令行调用 extract.py，不修改原文件
    """
    cmd = [
        "python", "extract.py",
        "--video_path", video_path,
        "--config", config_path,
        "--prompt", prompt,
        "--msg-len", str(msg_len),
        "--key", str(key),               # <--- [新增] 传递密钥
        "--target-bpf", str(target_bpf)  # <--- [新增] 传递物理容量
    ]

    try:
        # 执行命令并捕获输出
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            encoding='utf-8' # 防止中文乱码
        )
        
        # 从 stdout 中解析提取结果
        # 寻找 extract.py 打印的 "提取结果: XXXXX"
        output_log = result.stdout
        match = re.search(r"提取结果:\s*(.*)", output_log)
        
        if match:
            extracted_text = match.group(1).strip()
            return extracted_text
        else:
            print(f"警告: 无法从日志中解析结果。完整日志:\n{output_log[-500:]}") # 打印最后500字符
            return ""
            
    except Exception as e:
        print(f"执行 extract.py 失败: {e}")
        return ""

# ================= 主流程：基准测试循环 =================
def run_benchmark(original_video, config_yaml, prompt, secret_gt, override_msg_len=0, key=42, target_bpf=96):
    attacker = VideoAttacker()
    
    # 实验结果保存路径
    csv_file = "benchmark_results.csv"
    
    # 定义要跑的攻击类型 (对应论文的实验设置)
    # 格式: (攻击名称, 攻击函数, 参数字典)
    attack_suite = [
        ("No_Attack", None, {}), # 基准组
        ("H264_CRF23", attacker.h264_compress, {"crf": 23}), # 模拟微信/B站默认压缩
        ("H264_CRF28", attacker.h264_compress, {"crf": 28}), # 较强压缩
        ("H265_CRF28", attacker.h265_compress, {"crf": 28}), # 补齐 H.265
        ("H264_CRF33", attacker.h264_compress, {"crf": 33}), # 极端压缩 (论文中的 Severe)
        ("FPS_8", attacker.frame_rate_change, {"target_fps": 8}), # 掉帧攻击
        ("Scaling_0.5", attacker.resize_scaling, {"scale": 0.5}), # 缩略图攻击
        ("Bit_Error", attacker.bit_error_noise, {"error_rate": 0.00001}), # 补齐比特错误
    ]

    # 准备表头
    file_exists = os.path.isfile(csv_file)
    with open(csv_file, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Timestamp", "Attack_Type", "Params", "Accuracy", "BER", "Extracted_Msg"])

        base_dir = os.path.dirname(original_video)
        temp_dir = os.path.join(base_dir, "temp_attacks")
        os.makedirs(temp_dir, exist_ok=True)
        
        print(f"\n🚀 开始基准测试...")
        print(f"原始视频: {original_video}")
        print(f"真值信息: {secret_gt}\n")

        for name, func, params in attack_suite:
            print(f"正在进行测试: [{name}] ...", end="", flush=True)
            
            # 1. 生成攻击后的视频
            if func:
                attacked_video_name = f"attacked_{name}.mp4" # 注意：压缩后通常变为mp4
                attacked_video_path = os.path.join(temp_dir, attacked_video_name)
                func(original_video, attacked_video_path, **params)
            else:
                attacked_video_path = original_video # 无攻击直接用原片

            # 2. 调用 extract.py 提取
            if override_msg_len > 0:
                msg_bits_len = override_msg_len
            else:
                msg_bits_len = len(secret_gt) * 8 
            
            extracted_msg = run_extraction_blackbox(
                attacked_video_path, 
                prompt, 
                msg_bits_len, 
                config_yaml,
                key,         
                target_bpf   
            )

            # 3. 计算指标
            acc, ber = calculate_metrics(secret_gt, extracted_msg)

            # 4. 写入 CSV
            writer.writerow([
                os.path.basename(original_video), 
                name, 
                str(params), 
                f"{acc:.4f}", 
                f"{ber:.4f}", 
                extracted_msg
            ])
            f.flush() # 立即写入磁盘

            # 5. 打印状态
            status = "✅ PASS" if acc == 1.0 else ("⚠️ LOSS" if acc > 0.8 else "❌ FAIL")
            print(f" {status} | Acc: {acc*100:.2f}% | BER: {ber*100:.2f}% | 提取: {extracted_msg}")

    print(f"\n✨ 所有测试完成。结果已保存至 {csv_file}")

if __name__ == "__main__":
    # ================= 默认配置区域 (代码内兜底值) =================
    DEFAULT_VIDEO = "/data/yzj/animate1/AnimateDiff/samples/3_3_sparsectrl_sketch_RealisticVision-2026-02-26T17-56-56/sample/1-a-back-view-of-a-boy,-standing-on-the-ground,.gif"
    DEFAULT_CONFIG = "configs/prompts/3_sparsectrl/3_3_sparsectrl_sketch_RealisticVision.yaml"
    DEFAULT_PROMPT = "a back view of a boy, standing on the ground, looking at the sky, clouds, sunset, orange sky, beautiful sunlight, masterpieces"
    DEFAULT_SECRET = "My confidential message 123!"

    # ================= 命令行参数解析 =================
    parser = argparse.ArgumentParser(description="Video Steganography Benchmark script")
    
    parser.add_argument("--video_path", type=str, default=DEFAULT_VIDEO, help="目标视频路径")
    parser.add_argument("--config", type=str, default=DEFAULT_CONFIG, help="生成时使用的 YAML 配置文件路径")
    parser.add_argument("--prompt", type=str, default=DEFAULT_PROMPT, help="生成时使用的提示词")
    parser.add_argument("--secret-gt", type=str, default=DEFAULT_SECRET, help="真实的秘密信息文本")
    parser.add_argument("--msg-len", type=int, default=0, help="强制指定提取的比特长度 (默认 0 表示自动计算)")
    parser.add_argument("--key", type=int, default=42, help="共享密钥 (必须与生成时一致)")
    parser.add_argument("--target-bpf", type=int, default=96, help="目标物理容量 (如 96, 192, 384)")

    args = parser.parse_args()

    # ================= 运行 =================
    print(f"\n[Init] 视频路径: {args.video_path}")
    print(f"[Init] 配置文件: {args.config}")
    print(f"[Init] 使用密钥: {args.key}")
    print(f"[Init] 目标 BPF: {args.target_bpf}")
    
    run_benchmark(
        original_video=args.video_path, 
        config_yaml=args.config, 
        prompt=args.prompt, 
        secret_gt=args.secret_gt,
        override_msg_len=args.msg_len,
        key=args.key,               # <--- [新增]
        target_bpf=args.target_bpf  # <--- [新增]
    )
