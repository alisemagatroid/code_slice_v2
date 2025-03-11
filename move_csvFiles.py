import os
import shutil

#하나의 취약점점
def move_files(src_root, category_path):
    """
    src_root 내부의 .csv 파일이 포함된 디렉토리(src_dir)와 
    src_root에 직접 존재하는 .c, .cpp 파일을 찾아서 함께 이동.
    """
    if not os.path.isdir(src_root):
        print("[ERROR] 입력된 디렉토리가 올바르지 않습니다.")
        return
    
    src_dirs = [d for d in os.listdir(src_root) if os.path.isdir(os.path.join(src_root, d))]
    src_files = [f for f in os.listdir(src_root) if os.path.isfile(os.path.join(src_root, f))]

    for src_dir in src_dirs:
        src_path = os.path.join(src_root, src_dir)
        
        # 최종 목적지 경로 설정
        dest_path = os.path.join(category_path, src_dir)
        os.makedirs(dest_path, exist_ok=True)  # 디렉토리가 없다면 생성
        
        # .csv 파일 이동
        for file in os.listdir(src_path):
            if file.endswith(".csv"):
                src_file = os.path.join(src_path, file)
                dest_file = os.path.join(dest_path, file)
                shutil.move(src_file, dest_file)
                print(f"Moved: {src_file} -> {dest_file}")

        # 매칭되는 .c 또는 .cpp 파일 이동
        for src_file in src_files:
            file_name, file_ext = os.path.splitext(src_file)
            if file_ext in [".c", ".cpp"] and file_name == src_dir:
                src_file_path = os.path.join(src_root, src_file)
                dest_file_path = os.path.join(dest_path, src_file)
                shutil.move(src_file_path, dest_file_path)
                print(f"Moved: {src_file_path} -> {dest_file_path}")

        print(f"Finished processing directory: {src_dir}")

# parsing_dirs 내부의 여러 directory에 대해서 하나씩 처리
def process_parsing_dirs(parsing_dirs, dest_root):
    """ parsing_dirs 내부의 모든 parsing_XXX 디렉토리를 처리 """
    if not os.path.isdir(parsing_dirs):
        print("[ERROR] parsing_dirs 경로가 올바르지 않습니다.")
        return
    
    for src_root in os.listdir(parsing_dirs):
        src_root_path = os.path.join(parsing_dirs, src_root)
        if os.path.isdir(src_root_path) and src_root.startswith("parsing_"):
            category_name = src_root.split("parsing_")[-1]
            category_path = os.path.join(dest_root, category_name)
            os.makedirs(category_path, exist_ok=True)
            
            print(f"Processing: {src_root_path} -> {category_path}")
            move_files(src_root_path, category_path)


# argv[1]: parsing_dirs argv[2]: r_dirs
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python script.py <parsing_dirs> <destination_directory>")
    else:
        process_parsing_dirs(sys.argv[1], sys.argv[2])
