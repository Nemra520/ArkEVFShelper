import os
import sys
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox

from blchelper import decrypt_blc_file, convert_blc_to_json
from vfsext import process_bundle

def select_file(title, filetypes):
    """选择文件对话框"""
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(title=title, filetypes=filetypes)
    return file_path

def select_folder(title):
    """选择文件夹对话框"""
    root = tk.Tk()
    root.withdraw()
    folder_path = filedialog.askdirectory(title=title)
    return folder_path

def main():
    """主函数：解密BLC文件并提取内容"""
    print("=" * 60)
    print("BLC文件解密和内容提取工具")
    print("=" * 60)
    
    # 第一步：选择BLC文件
    print("\n第一步：选择BLC文件")
    blc_file = select_file(
        "选择BLC文件",
        [
            ("BLC文件", "*.blc"),
            ("所有文件", "*.*")
        ]
    )
    
    if not blc_file:
        print("未选择BLC文件，程序退出")
        return
    
    blc_path = Path(blc_file)
    print(f"已选择: {blc_path.name}")
    
    # 第二步：解密BLC文件并转换为JSON
    print("\n第二步：解密BLC文件...")
    try:
        decrypted_path = decrypt_blc_file(blc_file)
        print(f"解密成功: {Path(decrypted_path).name}")
    except Exception as e:
        messagebox.showerror("解密失败", f"解密BLC文件失败:\n{str(e)}")
        print(f"解密失败: {e}")
        input("按回车键退出...")
        return
    
    # 第三步：转换为JSON
    print("\n第三步：转换为JSON...")
    json_path = blc_path.parent / (blc_path.stem + ".json")
    try:
        convert_blc_to_json(decrypted_path, str(json_path))
        print(f"JSON生成成功: {json_path.name}")
        
        # 删除临时解密文件
        os.remove(decrypted_path)
        print("临时解密文件已删除")
    except Exception as e:
        messagebox.showerror("转换失败", f"转换为JSON失败:\n{str(e)}")
        print(f"转换失败: {e}")
        if os.path.exists(decrypted_path):
            os.remove(decrypted_path)
        input("按回车键退出...")
        return
    
    # 第四步：使用BLC文件所在文件夹作为CHK文件夹
    print("\n第四步：查找CHK文件...")
    chk_folder = blc_path.parent
    print(f"使用文件夹: {chk_folder}")
    
    # 第五步：提取文件
    print("\n第五步：提取文件...")
    try:
        output_base = chk_folder
        process_bundle(str(json_path), str(chk_folder), str(output_base))
        
        # 删除JSON文件
        os.remove(json_path)
        print("JSON配置文件已删除")
        
        print("\n" + "=" * 60)
        print("所有操作完成！")
        print("=" * 60)
        messagebox.showinfo("完成", "BLC文件解密和内容提取完成！")
    except Exception as e:
        messagebox.showerror("提取失败", f"提取文件失败:\n{str(e)}")
        print(f"提取失败: {e}")
        import traceback
        traceback.print_exc()
    
    input("\n按回车键退出...")

if __name__ == "__main__":
    main()
