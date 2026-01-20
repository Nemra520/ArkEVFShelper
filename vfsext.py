import os
import json
import base64
import tkinter as tk
from tkinter import filedialog
from pathlib import Path
import hashlib
from Crypto.Cipher import ChaCha20

def select_folder():
    """弹出文件夹选择对话框"""
    root = tk.Tk()
    root.withdraw()
    folder_path = filedialog.askdirectory(title="请选择包含JSON和CHK文件的文件夹")
    return folder_path

def chacha20_decrypt(key, nonce, ciphertext):
    """ChaCha20解密（跳过前64字节密钥流，相当于counter=1）"""
    cipher = ChaCha20.new(key=key, nonce=nonce)
    cipher.seek(64)  # 跳过64字节，等效counter=1
    return cipher.decrypt(ciphertext)

def calculate_md5(data):
    """计算MD5"""
    return hashlib.md5(data).hexdigest()

def process_bundle(json_path, chk_folder, output_base):
    """处理JSON配置并提取文件"""
    # 读取JSON
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # 获取配置信息
    version = data['version']
    group_cfg_name = data['groupCfgName']
    all_chunks = data['allChunks']
    
    # 创建输出目录
    output_dir = Path(output_base) / group_cfg_name
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"开始提取文件到: {output_dir}")
    print(f"版本: {version}, 块数量: {len(all_chunks)}")
    
    # Base64解码密钥（32字节）
    key_base64 = "6VsxesT4KFadI6hr8nHctT6Eb6dckk1nHbqOOPTKUuE="
    key = base64.b64decode(key_base64)
    print(f"密钥长度: {len(key)} bytes")
    
    # 处理每个chunk
    for chunk in all_chunks:
        chunk_md5_name = chunk['md5Name']
        chk_file_name = f"{chunk_md5_name}.chk"
        chk_path = Path(chk_folder) / chk_file_name
        
        if not chk_path.exists():
            print(f"警告: 找不到CHK文件 {chk_path}")
            continue
        
        print(f"\n处理CHK文件: {chk_file_name} (大小: {chk_path.stat().st_size} bytes)")
        
        # 打开CHK文件
        with open(chk_path, 'rb') as chk_file:
            # 处理每个文件
            for file_info in chunk['files']:
                file_name = file_info['fileName']
                file_data_md5 = file_info['fileDataMD5']
                offset = file_info['offset']
                length = file_info['len']
                b_use_encrypt = file_info.get('bUseEncrypt', False)
                iv_seed = file_info.get('ivSeed', None)
                
                # 读取数据块
                chk_file.seek(offset)
                file_data = chk_file.read(length)
                
                if len(file_data) != length:
                    print(f"  警告: 读取数据长度不匹配 {file_name} (期望{length}, 实际{len(file_data)})")
                    continue
                
                # 解密处理
                if b_use_encrypt:
                    if iv_seed is None:
                        print(f"  警告: 文件标记加密但缺少ivSeed {file_name}")
                        continue
                    
                    # 准备nonce: version(小端4字节) + ivSeed(小端4字节)
                    version_bytes = version.to_bytes(4, byteorder='little')
                    iv_seed_bytes = iv_seed.to_bytes(8, byteorder='little')
                    nonce = version_bytes + iv_seed_bytes
                    
                    try:
                        # 解密（内部会跳过64字节）
                        file_data = chacha20_decrypt(key, nonce, file_data)
                        print(f"  解密文件: {file_name} (ivSeed: {iv_seed})")
                    except Exception as e:
                        print(f"  解密失败: {file_name} - {e}")
                        continue
                
                # MD5校验
                actual_md5 = calculate_md5(file_data)
                if actual_md5.lower() != file_data_md5.lower():
                    print(f"  警告: MD5校验失败 {file_name}")
                    print(f"    期望: {file_data_md5}")
                    print(f"    实际: {actual_md5}")
                else:
                    print(f"  MD5校验通过: {file_name}")
                
                # 创建输出文件路径
                output_file = output_dir / file_name
                output_file.parent.mkdir(parents=True, exist_ok=True)
                
                # 写入文件
                try:
                    with open(output_file, 'wb') as out_f:
                        out_f.write(file_data)
                    print(f"  提取成功: {file_name} ({len(file_data)} bytes)")
                except Exception as e:
                    print(f"  写入失败: {file_name} - {e}")
    
    print(f"\n提取完成！文件保存在: {output_dir}")

def main():
    """主函数"""
    print("="*60)
    print("明日方舟: 终末地 BLC文件提取工具")
    print("="*60)
    
    # 选择文件夹
    folder = select_folder()
    if not folder:
        print("未选择文件夹，程序退出")
        input("\n按回车键退出...")
        return
    
    folder_path = Path(folder)
    print(f"选择文件夹: {folder_path}\n")
    
    # 查找JSON文件
    json_files = list(folder_path.glob("*.json"))
    if not json_files:
        print("错误: 文件夹中未找到JSON文件")
        input("\n按回车键退出...")
        return
    
    json_file = json_files[0]
    print(f"使用JSON配置: {json_file.name}")
    
    try:
        process_bundle(json_file, folder_path, folder_path)
        print("\n✓ 所有文件处理完成！")
    except Exception as e:
        print(f"\n✗ 处理过程中出错: {e}")
        import traceback
        traceback.print_exc()
    
    input("\n按回车键退出...")

if __name__ == "__main__":
    main()
