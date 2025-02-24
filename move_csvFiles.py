""" 디렉토리 안에 export.json이 있는 
Returns:
    _type_: _description_
"""

import os
import shutil

def get_matched_dir(target_dir, dest_dirs):
    """
    대상 디렉토리의 '_구조'를 일정 부분 유지한 상태에서 비교
    """
    target_parts = target_dir.split("_")
    for dest_dir in dest_dirs:
        dest_parts = dest_dir.split("_")
        if target_parts[-2:] == dest_parts[-2:]:  # 마지막 두 개만 비교
            return dest_dir
    return None


def move_csv_files(src_root, dest_root):
    """
    src_root 내부의 모든 디렉토리를 순회하면서 .csv 파일을 
    dest_root 내부에서 매칭되는 디렉토리로 이동
    """
    if not os.path.isdir(src_root) or not os.path.isdir(dest_root):
        print("[ERROR] 입력된 디렉토리가 올바르지 않습니다.")
        return
    
    src_dirs = [d for d in os.listdir(src_root) if os.path.isdir(os.path.join(src_root, d))]
    dest_dirs = [d for d in os.listdir(dest_root) if os.path.isdir(os.path.join(dest_root, d))]
    
    for src_dir in src_dirs:
        src_path = os.path.join(src_root, src_dir)
        matched_dest_dir = get_matched_dir(src_dir, dest_dirs)
        
        if matched_dest_dir:
            dest_path = os.path.join(dest_root, matched_dest_dir)
            
            # .csv 파일만 이동
            for file in os.listdir(src_path):
                if file.endswith(".csv"):
                    src_file = os.path.join(src_path, file)
                    dest_file = os.path.join(dest_path, file)
                    
                    shutil.move(src_file, dest_file)  # 기존 파일이 있으면 덮어쓰기
                    print(f"Moved: {src_file} -> {dest_file}")
        else:
            print(f"[WARNING] '{src_dir}'에 매칭되는 대상 디렉토리가 없습니다.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python script.py <source_directory> <destination_directory>")
    else:
        move_csv_files(sys.argv[1], sys.argv[2])
