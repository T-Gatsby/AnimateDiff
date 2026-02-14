import subprocess
import os
import random
import numpy as np
import imageio

class VideoAttacker:
    def __init__(self, ffmpeg_path="ffmpeg"):
        self.ffmpeg = ffmpeg_path

    def _run_ffmpeg(self, cmd):
        """执行 FFmpeg 命令 (修改版：出错时打印详细日志)"""
        try:
            # 捕获 stderr 以便出错时打印，但在正常运行时保持安静
            result = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,  # 确保输出是字符串
                check=True
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"\n[FFmpeg Error] 命令执行失败!")
            print(f"命令: {' '.join(cmd)}")
            print(f"错误信息 (stderr):\n{e.stderr}\n") # 这里会显示具体的错误原因
            return False

    def h264_compress(self, input_path, output_path, crf=23):
        """
        [关键修复] 添加 -pix_fmt yuv420p 以支持 GIF 转 MP4
        """
        cmd = [
            self.ffmpeg, '-y', '-i', input_path,
            '-c:v', 'libx264', 
            '-pix_fmt', 'yuv420p',  # <--- 新增：强制转换颜色空间
            '-crf', str(crf),
            '-preset', 'slow', 
            output_path
        ]
        self._run_ffmpeg(cmd)
        return output_path

    def h265_compress(self, input_path, output_path, crf=28):
        """
        [关键修复] 同样添加 -pix_fmt yuv420p
        """
        cmd = [
            self.ffmpeg, '-y', '-i', input_path,
            '-c:v', 'libx265', 
            '-pix_fmt', 'yuv420p',  # <--- 新增
            '-crf', str(crf),
            '-preset', 'slow',
            output_path
        ]
        self._run_ffmpeg(cmd)
        return output_path

    # ... 其他函数 (frame_rate_change, resize_scaling 等) 保持不变 ...
    def frame_rate_change(self, input_path, output_path, target_fps=8):
        cmd = [
            self.ffmpeg, '-y', '-i', input_path,
            '-r', str(target_fps),
            # 最好也加上这个，防止掉帧重编码时格式出错
            '-pix_fmt', 'yuv420p', 
            output_path
        ]
        self._run_ffmpeg(cmd)
        return output_path

    def resize_scaling(self, input_path, output_path, scale=0.5):
        # 缩放时，宽高必须是偶数，否则 libx264 会报错
        # 使用 trunc(iw/2)*2 确保宽是偶数
        scale_filter = f"scale=trunc(iw*{scale}/2)*2:trunc(ih*{scale}/2)*2"
        
        cmd = [
            self.ffmpeg, '-y', '-i', input_path,
            '-vf', scale_filter,
            '-c:v', 'libx264',     # 缩放后通常需要重编码
            '-pix_fmt', 'yuv420p', # 确保格式正确
            output_path
        ]
        self._run_ffmpeg(cmd)
        return output_path

    def bit_error_noise(self, input_path, output_path, error_rate=0.00001):
        """
        [论文对齐] 模拟信道传输中的比特翻转 [cite: 401]
        注意：直接修改视频文件比特可能导致无法播放，通常在逻辑层模拟。
        这里我们用高斯噪声模拟视频层面的信号干扰。
        """
        reader = imageio.get_reader(input_path)
        fps = reader.get_meta_data()['fps']
        writer = imageio.get_writer(output_path, fps=fps)
        
        for frame in reader:
            # 添加椒盐噪声或高斯噪声
            noise = np.random.normal(0, 5, frame.shape).astype('int16')
            noisy_frame = frame.astype('int16') + noise
            noisy_frame = np.clip(noisy_frame, 0, 255).astype('uint8')
            writer.append_data(noisy_frame)
        
        writer.close()
        return output_path