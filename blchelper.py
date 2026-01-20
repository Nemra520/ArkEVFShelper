import struct
import sys
import os
import json
import traceback
from typing import List, Tuple, Any, Dict
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import ChaCha20
from base64 import b64decode

# 固定密钥（来自逆向分析）
CHACHA_KEY = b64decode("6VsxesT4KFadI6hr8nHctT6Eb6dckk1nHbqOOPTKUuE=")

class UInt128:
    def __init__(self, data: bytes):
        self.data = data
    def hex(self) -> str:
        return self.data.hex()
    def __str__(self):
        return self.hex()
    def to_serializable(self):
        return self.hex()

class FVFBlockFileInfo:
    def __init__(self):
        self.fileName = ""
        self.fileNameHash = 0
        self.fileChunkMD5Name = None
        self.fileDataMD5 = None
        self.offset = 0
        self.len = 0
        self.blockType = 0
        self.bUseEncrypt = False
        self.ivSeed = 0
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "fileName": self.fileName,
            "fileNameHash": f"{self.fileNameHash:016X}",
            "fileChunkMD5Name": self.fileChunkMD5Name.to_serializable() if self.fileChunkMD5Name else None,
            "fileDataMD5": self.fileDataMD5.to_serializable() if self.fileDataMD5 else None,
            "offset": self.offset,
            "len": self.len,
            "blockType": self.blockType,
            "bUseEncrypt": self.bUseEncrypt
        }
        if self.bUseEncrypt:
            result["ivSeed"] = self.ivSeed
        return result

class FVFBlockChunkInfo:
    def __init__(self):
        self.md5Name = None
        self.contentMD5 = None
        self.length = 0
        self.blockType = 0
        self.filesCount = 0
        self.files = []  # type: List[FVFBlockFileInfo]
    def to_dict(self) -> Dict[str, Any]:
        return {
            "md5Name": self.md5Name.to_serializable() if self.md5Name else None,
            "contentMD5": self.contentMD5.to_serializable() if self.contentMD5 else None,
            "length": self.length,
            "blockType": self.blockType,
            "filesCount": self.filesCount,
            "files": [file_info.to_dict() for file_info in self.files]
        }

class VFBlockMainInfo:
    def __init__(self):
        self.version = 0
        self.groupCfgName = ""
        self.groupCfgHashName = 0
        self.groupFileInfoNum = 0
        self.groupChunksLength = 0
        self.blockType = 0
        self.allChunksCount = 0
        self.allChunks = []  # type: List[FVFBlockChunkInfo]
    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "groupCfgName": self.groupCfgName,
            "groupCfgHashName": f"{self.groupCfgHashName:08X}",
            "groupFileInfoNum": self.groupFileInfoNum,
            "groupChunksLength": self.groupChunksLength,
            "blockType": self.blockType,
            "allChunksCount": self.allChunksCount,
            "allChunks": [chunk.to_dict() for chunk in self.allChunks]
        }

def parse_fvf_block_file_info(data: bytes, offset: int) -> Tuple[FVFBlockFileInfo, int]:
    """解析单个文件信息"""
    file_info = FVFBlockFileInfo()
    # 解析文件名
    name_len = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    if name_len > 0:
        file_info.fileName = data[offset:offset+name_len].decode('utf-8')
        offset += name_len
    # 解析文件名哈希
    file_info.fileNameHash = struct.unpack_from('<Q', data, offset)[0]
    offset += 8
    # 解析文件块MD5
    file_info.fileChunkMD5Name = UInt128(data[offset:offset+16])
    offset += 16
    # 解析文件数据MD5
    file_info.fileDataMD5 = UInt128(data[offset:offset+16])
    offset += 16
    # 解析偏移和长度
    file_info.offset = struct.unpack_from('<q', data, offset)[0]
    offset += 8
    file_info.len = struct.unpack_from('<q', data, offset)[0]
    offset += 8
    # 解析块类型
    file_info.blockType = struct.unpack_from('<B', data, offset)[0]
    offset += 1
    # 解析是否加密
    encrypt_flag = struct.unpack_from('<B', data, offset)[0]
    file_info.bUseEncrypt = encrypt_flag != 0
    offset += 1
    # 如果加密，解析ivSeed
    if file_info.bUseEncrypt:
        file_info.ivSeed = struct.unpack_from('<q', data, offset)[0]
        offset += 8
    return file_info, offset

def parse_fvf_block_chunk_info(data: bytes, offset: int) -> Tuple[FVFBlockChunkInfo, int]:
    """解析单个块信息"""
    chunk_info = FVFBlockChunkInfo()
    # 解析MD5名称
    chunk_info.md5Name = UInt128(data[offset:offset+16])
    offset += 16
    # 解析内容MD5
    chunk_info.contentMD5 = UInt128(data[offset:offset+16])
    offset += 16
    # 解析块长度
    chunk_info.length = struct.unpack_from('<q', data, offset)[0]
    offset += 8
    # 解析块类型
    chunk_info.blockType = struct.unpack_from('<B', data, offset)[0]
    offset += 1
    # 解析文件数量
    chunk_info.filesCount = struct.unpack_from('<i', data, offset)[0]
    offset += 4
    # 解析文件信息数组
    chunk_info.files = []
    for _ in range(chunk_info.filesCount):
        file_info, offset = parse_fvf_block_file_info(data, offset)
        chunk_info.files.append(file_info)
    return chunk_info, offset

def parse_vf_block_main_info(data: bytes) -> VFBlockMainInfo:
    """完整解析BLC文件"""
    main_info = VFBlockMainInfo()
    offset = 0
    # 解析版本 (4字节)
    main_info.version = struct.unpack_from('<i', data, offset)[0]
    offset += 4
    # 解析groupCfgName
    name_len = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    if name_len > 0:
        main_info.groupCfgName = data[offset:offset+name_len].decode('utf-8')
        offset += name_len
    # 解析groupCfgHashName (大端序，仅前4字节有效)
    hash_bytes = data[offset:offset+4]
    main_info.groupCfgHashName = int.from_bytes(hash_bytes, byteorder='big')
    offset += 8
    # 跳过8字节，但只有前4字节有效
    # 解析文件总数
    main_info.groupFileInfoNum = struct.unpack_from('<i', data, offset)[0]
    offset += 4
    # 解析所有块的总长度
    main_info.groupChunksLength = struct.unpack_from('<q', data, offset)[0]
    offset += 8
    # 解析块类型
    main_info.blockType = struct.unpack_from('<B', data, offset)[0]
    offset += 1
    # 解析所有块的数量
    main_info.allChunksCount = struct.unpack_from('<i', data, offset)[0]
    offset += 4
    # 解析所有块信息
    main_info.allChunks = []
    for i in range(main_info.allChunksCount):
        chunk_info, offset = parse_fvf_block_chunk_info(data, offset)
        main_info.allChunks.append(chunk_info)
    return main_info

def convert_blc_to_json(input_path: str, output_path: str):
    """将BLC文件转换为JSON，指定输出路径"""
    try:
        # 读取文件
        with open(input_path, "rb") as f:
            decrypted_data = f.read()
        # 检查文件大小
        if len(decrypted_data) < 40:
            # 最小可能的大小
            raise ValueError("文件太小，不是有效的BLC文件")
        # 解析BLC文件
        main_info = parse_vf_block_main_info(decrypted_data)
        # 保存为JSON到指定路径
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(main_info.to_dict(), f, indent=2, ensure_ascii=False)
        return output_path
    except Exception as e:
        error_msg = f"转换失败: {str(e)}\n{traceback.format_exc()}"
        raise Exception(error_msg)

def decrypt_blc_file(filepath):
    """解密BLC文件"""
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        if len(data) < 12:
            raise ValueError("文件太小，无法包含有效的 Nonce")
        nonce = data[:12]
        ciphertext = data[12:]
        # 初始化 ChaCha20 解密器
        cipher = ChaCha20.new(key=CHACHA_KEY, nonce=nonce)
        # 跳过第一个 64 字节块（模拟 counter=1）
        cipher.seek(64)
        decrypted = cipher.decrypt(ciphertext)
        # 前四字节替换成加密文件的前四字节
        decrypted = data[:4] + decrypted[4:]
        # 输出文件路径：原文件名 + .decrypted.bin
        output_path = filepath + ".decrypted.bin"
        with open(output_path, 'wb') as out_f:
            out_f.write(decrypted)
        return output_path
    except Exception as e:
        raise e

def show_completion_message(input_path, output_path, error=None):
    """显示完成消息，只有一个确定按钮"""
    root = tk.Tk()
    root.withdraw()  # 隐藏主窗口
    
    try:
        if error:
            messagebox.showerror("转换失败", f"无法转换文件:\n{input_path}\n\n错误: {error}")
        else:
            messagebox.showinfo("转换成功", f"文件已成功转换:\n{input_path}\n\nJSON输出:\n{output_path}")
    finally:
        root.destroy()

if __name__ == "__main__":
    # 创建隐藏的主窗口用于文件对话框
    root = tk.Tk()
    root.withdraw()
    
    # 显示文件选择对话框
    file_path = filedialog.askopenfilename(
        title="选择BLC文件",
        filetypes=[
            ("BLC文件", "*.blc *.bin *.dat *.bytes"),
            ("所有文件", "*.*")
        ]
    )
    
    # 如果用户取消了选择，直接退出
    if not file_path:
        sys.exit(0)
    
    # 获取文件扩展名
    file_ext = os.path.splitext(file_path)[1].lower()
    
    # 确定最终JSON输出路径（与原始文件同名，仅扩展名改为.json）
    json_path = os.path.splitext(file_path)[0] + '.json'
    
    # 如果是 .blc，先解密
    if file_ext == '.blc':
        try:
            decrypted_path = decrypt_blc_file(file_path)
            temp_file = decrypted_path
        except Exception as e:
            show_completion_message(file_path, "", f"解密失败: {str(e)}")
            sys.exit(1)
    else:
        temp_file = file_path
    
    # 执行转换
    try:
        # 使用预定义的json_path作为输出路径
        output_path = convert_blc_to_json(temp_file, json_path)
        
        # 如果是临时解密文件，删除它
        if file_ext == '.blc' and os.path.exists(temp_file):
            os.remove(temp_file)
            
        show_completion_message(file_path, json_path)
    except Exception as e:
        # 清理临时文件
        if file_ext == '.blc' and os.path.exists(temp_file):
            os.remove(temp_file)
        show_completion_message(file_path, "", str(e))
