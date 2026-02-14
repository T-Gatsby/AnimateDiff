#!/data/wj/anaconda3/envs/animatediff/bin/python
import os
import sys

def find_model():
    print("🔍 查找模型文件...")
    
    # 检查当前目录
    print(f"当前目录: {os.getcwd()}")
    
    # 检查可能的模型位置
    locations = [
        "models/StableDiffusion/stable-diffusion-v1-5",
        "models/StableDiffusion/",
        "../models/StableDiffusion/",
        "stable-diffusion-v1-5",
        "runwayml/stable-diffusion-v1-5"
    ]
    
    for loc in locations:
        abs_path = os.path.abspath(loc)
        exists = os.path.exists(abs_path)
        print(f"{loc}: {'✅' if exists else '❌'} -> {abs_path}")
        if exists:
            if os.path.isdir(abs_path):
                items = os.listdir(abs_path)
                print(f"   包含 {len(items)} 个项目")
                for item in items[:3]:  # 显示前3个
                    print(f"     - {item}")
    
    # 检查 HuggingFace 缓存
    cache_path = os.path.expanduser("~/.cache/huggingface/hub")
    if os.path.exists(cache_path):
        print(f"\n📦 HuggingFace 缓存目录: {cache_path}")
        # 查找可能的模型缓存
        for root, dirs, files in os.walk(cache_path):
            if "stable-diffusion" in root.lower():
                print(f"  找到: {root}")
                break

if __name__ == "__main__":
    find_model()