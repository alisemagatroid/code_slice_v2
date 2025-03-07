import os
import shutil

"""
def get_matched_dir(src_dir, dest_dirs):
    
    대상 디렉토리의 '_구조'를 일정 부분 유지한 상태에서 비교
    
    target_parts = src_dir.split("_")
    for dest_dir in dest_dirs:
        dest_parts = dest_dir.split("_")
        if target_parts[-2:] == dest_parts[-2:]:  # 마지막 두 개만 비교
            return dest_dir
    return None


def move_files(src_root, dest_root):
    
    src_root 내부의 모든 디렉토리를 순회하면서 .csv, .c, .cpp 파일을 
    dest_root 내부에서 매칭되는 디렉토리로 이동
    
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
        else:
            # 매칭되는 디렉토리가 없으면 src_dir 이름으로 새 디렉토리를 생성
            dest_path = os.path.join(dest_root, src_dir)
            os.makedirs(dest_path, exist_ok=True)  # 디렉토리가 없다면 생성
        
        # .csv, .c, .cpp 파일을 이동
        for file in os.listdir(src_path):
            if file.endswith(".csv") or file.endswith(".c") or file.endswith(".cpp"):
                src_file = os.path.join(src_path, file)
                dest_file = os.path.join(dest_path, file)
                
                shutil.move(src_file, dest_file)  # 기존 파일이 있으면 덮어쓰기
                print(f"Moved: {src_file} -> {dest_file}")
                
        print(f"Finished processing directory: {src_dir}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python script.py <source_directory> <destination_directory>")
    else:
        move_files(sys.argv[1], sys.argv[2])
"""

def move_files(src_root, dest_root):
    """
    src_root 내부의 .csv 파일이 포함된 디렉토리(src_dir)와 
    src_root에 직접 존재하는 .c, .cpp 파일을 찾아서 함께 이동.
    """
    if not os.path.isdir(src_root) or not os.path.isdir(dest_root):
        print("[ERROR] 입력된 디렉토리가 올바르지 않습니다.")
        return
    
    src_dirs = [d for d in os.listdir(src_root) if os.path.isdir(os.path.join(src_root, d))]
    src_files = [f for f in os.listdir(src_root) if os.path.isfile(os.path.join(src_root, f))]

    for src_dir in src_dirs:
        src_path = os.path.join(src_root, src_dir)
        
        # 매칭되는 디렉토리가 없으면 src_dir 이름으로 새 디렉토리를 생성
        dest_path = os.path.join(dest_root, src_dir)
        os.makedirs(dest_path, exist_ok=True)  # 디렉토리가 없다면 생성
        
        # .csv 파일 이동
        for file in os.listdir(src_path):
            if file.endswith(".csv"):
                src_file = os.path.join(src_path, file)
                dest_file = os.path.join(dest_path, file)
                shutil.move(src_file, dest_file)  # 기존 파일이 있으면 덮어쓰기
                print(f"Moved: {src_file} -> {dest_file}")

        # 매칭되는 .c 또는 .cpp 파일이 있는지 확인 후 함께 이동
        for src_file in src_files:
            file_name, file_ext = os.path.splitext(src_file)
            if file_ext in [".c", ".cpp"] and file_name == src_dir:
                src_file_path = os.path.join(src_root, src_file)
                dest_file_path = os.path.join(dest_path, src_file)
                shutil.move(src_file_path, dest_file_path)
                print(f"Moved: {src_file_path} -> {dest_file_path}")

        print(f"Finished processing directory: {src_dir}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python script.py <source_directory> <destination_directory>")
    else:
        move_files(sys.argv[1], sys.argv[2])