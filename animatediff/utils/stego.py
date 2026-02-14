import torch
import numpy as np
import scipy.fftpack
from einops import rearrange

class StegoProcessor:
    """
    ✅ 论文复现版: 基于秘密信息映射的生成式视频隐写
    核心原理: Secret -> IDCT -> Gaussian Noise -> Video Generation
    参考文献: [cite: 64, 241, 263]
    """
    def __init__(self, height, width, video_length, channels=4, downsample_factor=8, key=42):
        self.h_latent = height // downsample_factor
        self.w_latent = width // downsample_factor
        self.frames = video_length
        self.channels = channels
        self.key = key  # 共享密钥
        
        # 计算总的隐向量维度 (C * F * H * W)
        self.total_elements = self.channels * self.frames * self.h_latent * self.w_latent
        
        print(f"[Stego Init] 全维映射模式: {self.channels}x{self.frames}x{self.h_latent}x{self.w_latent}")
        print(f"[Stego Init] 总容量: {self.total_elements} (浮点数容量)")
        print(f"[Stego Init] 使用密钥: {self.key}")

    def _idct2_2d(self, matrix):
        """
        对应论文公式(8): IDCT变换
        对矩阵的最后两维进行 2D IDCT
        """
        # scipy.fftpack.idct 默认是对最后一个轴操作
        # norm='ortho' 保证变换的正交性，这是分布变换的关键 [cite: 263]
        return scipy.fftpack.idct(
            scipy.fftpack.idct(matrix, axis=-1, norm='ortho'), 
            axis=-2, norm='ortho'
        )

    def _dct2_2d(self, matrix):
        """
        对应论文公式(11): DCT变换提取
        """
        return scipy.fftpack.dct(
            scipy.fftpack.dct(matrix, axis=-1, norm='ortho'), 
            axis=-2, norm='ortho'
        )

    def prepare_secret_noise(self, message_bits: str, device='cuda', dtype=torch.float32, target_bpf=96):
        """
        生成含密噪声 (修改版：支持固定 BPF 对齐论文实验)
        target_bpf: 目标每帧嵌入比特数 (默认96, 可选192, 384)
        """
        print(f">>> [Stego] 正在执行论文算法: Secret -> IDCT -> Gaussian Noise")
        
        # 1. 准备原始秘密信息
        bits = np.array([int(b) for b in message_bits])
        
        # [核心修改] --- 强制对齐论文容量 ---
        if target_bpf > 0:
            target_len = int(target_bpf * self.frames) # 例如 96 * 16 = 1536 bits
            current_len = len(bits)
            
            if current_len < target_len:
                # 如果信息太短，循环填充直到达到目标长度 (保证 payload 填满 BPF)
                repeats_needed = (target_len // current_len) + 1
                bits = np.tile(bits, repeats_needed)[:target_len]
                print(f">>> [Capacity] 信息过短，已循环填充至 {target_len} bits (对应 {target_bpf} bpf)")
            elif current_len > target_len:
                # 如果信息太长，截断
                bits = bits[:target_len]
                print(f">>> [Capacity] 信息过长，已截断至 {target_len} bits (对应 {target_bpf} bpf)")
            else:
                print(f">>> [Capacity] 信息长度完美匹配 {target_len} bits")
        # ------------------------------------

        raw_signal = bits * 2 - 1  # {0, 1} -> {-1, 1}
        
        # 2. 重复嵌入 (Repeated Embedding)
        # 这里计算的是：在这个 BPF 下，整个 Latent 空间能容纳多少次完整的 Payload
        msg_len = len(raw_signal)
        repeats = self.total_elements // msg_len
        
        full_signal = np.tile(raw_signal, repeats)
        remainder = self.total_elements - len(full_signal)
        if remainder > 0:
            # 填充剩余部分
            padding = np.random.randint(0, 2, remainder) * 2 - 1
            full_signal = np.concatenate([full_signal, padding])
        
        print(f">>> [Stego] 最终Payload长度: {msg_len} (BPF={msg_len/self.frames:.1f})")
        print(f">>> [Stego] 空间冗余重复次数: {repeats} (Robustness)")
        
        # 3. 伪随机置乱
        np.random.seed(self.key)
        permutation = np.random.permutation(self.total_elements)
        scrambled_signal = full_signal[permutation]
        
        # 4. 重塑形状
        m_reshape = scrambled_signal.reshape(1, self.channels, self.frames, self.h_latent, self.w_latent)
        
        # 5. IDCT 变换
        stego_noise_np = np.zeros_like(m_reshape, dtype=np.float32)
        for c in range(self.channels):
            for f in range(self.frames):
                stego_noise_np[0, c, f] = self._idct2_2d(m_reshape[0, c, f])
        
        # 6. 统计修正
        stego_noise = torch.from_numpy(stego_noise_np).to(device=device, dtype=dtype)
        mean = stego_noise.mean()
        std = stego_noise.std()
        print(f">>> [Stego] 变换后分布: Mean={mean:.4f}, Std={std:.4f}")
        stego_noise = (stego_noise - mean) / (std + 1e-8)
        
        return stego_noise

    def recover_message(self, latents, original_msg_len, actual_msg_len=None):
        """
        增强版提取: 
        1. 第一层: 从 latent 恢复出 BPF 对齐的物理数据 (例如 1536 bits)
        2. 第二层: 如果已知实际信息较短，利用剩余空间进行二次投票 (自适应增强)
        """
        if latents.dtype != torch.float32: latents = latents.float()
        latents_np = latents.cpu().numpy()
        
        # 1. DCT 变换 & 2. 展平 (保持不变)
        recovered_m = np.zeros_like(latents_np)
        for c in range(self.channels):
            for f in range(self.frames):
                recovered_m[0, c, f] = self._dct2_2d(latents_np[0, c, f])
        flattened_signal = recovered_m.flatten()
        
        # 3. 逆置乱 (保持不变)
        np.random.seed(self.key)
        permutation = np.random.permutation(self.total_elements)
        inv_permutation = np.argsort(permutation)
        descrambled_signal = flattened_signal[inv_permutation]
        
        # 4. 第一层投票: 物理层恢复 (从 Total -> 1536)
        # 这一步保证了我们拿到了正确的“物理帧数据”
        repeats_outer = self.total_elements // original_msg_len
        
        if repeats_outer == 0: 
            # 极端情况：总容量还不够填一次 BPF，直接截断
            return (descrambled_signal[:original_msg_len] > 0).astype(int)
        
        valid_signal = descrambled_signal[:repeats_outer * original_msg_len]
        reshaped = valid_signal.reshape(repeats_outer, original_msg_len)
        averaged_physical = reshaped.mean(axis=0) # 得到 1536 长度的软信息
        
        # ================= [新增: 第二层自适应投票] =================
        # 只有当用户提供了实际长度，且实际长度小于物理长度时，才触发增强
        if actual_msg_len is not None and actual_msg_len > 0:
            if original_msg_len > actual_msg_len:
                # 计算内部可以容纳多少次完整重复
                repeats_inner = original_msg_len // actual_msg_len
                
                # 只有重复次数 >= 2 才有投票意义
                if repeats_inner >= 2:
                    print(f">>> [Recover] 触发自适应增强: 物理层 {original_msg_len} -> 有效层 {actual_msg_len} (重复 {repeats_inner} 次)")
                    
                    # 截取整数倍部分进行投票
                    valid_inner = averaged_physical[:repeats_inner * actual_msg_len]
                    reshaped_inner = valid_inner.reshape(repeats_inner, actual_msg_len)
                    final_soft = reshaped_inner.mean(axis=0)
                    
                    return (final_soft > 0).astype(int)
        # ==========================================================
        
        # 如果不需要/不能进行二次投票，直接硬判决返回物理层数据
        return (averaged_physical > 0).astype(int)

    @staticmethod
    def str_to_bits(s):
        result = []
        for c in s:
            bits = bin(ord(c))[2:].zfill(8)
            result.extend([int(b) for b in bits])
        return "".join(map(str, result))

    @staticmethod
    def bits_to_str(bits):
        chars = []
        for i in range(0, len(bits), 8):
            byte = bits[i:i+8]
            if len(byte) < 8: break
            try:
                char_code = int("".join(map(str, byte)), 2)
                # 过滤非打印字符
                if 32 <= char_code <= 126:
                    chars.append(chr(char_code))
                else:
                    chars.append('?')
            except:
                chars.append('?')
        return "".join(chars)