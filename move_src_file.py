import os
import shutil
from pathlib import Path  # pathlib 사용

def move_c_and_cpp_files_to_directory(base_dir):
    base_dir = os.path.abspath(base_dir)  # 절대 경로 변환

    for dir_name in os.listdir(base_dir):
        dir_path = os.path.join(base_dir, dir_name)  # 현재 탐색 중인 디렉토리

        if os.path.isdir(dir_path):
            print(f"Processing directory: {dir_path}")

            for file_name in os.listdir(dir_path):
                file_path = os.path.join(dir_path, file_name)

                if file_name.endswith(('.c', '.cpp')):
                    print(f"Found file: {file_name}")

                    # 확장자 제거한 파일명을 기반으로 같은 폴더 내에서 대상 디렉토리 찾기
                    target_dir_name = Path(file_name).stem
                    target_dir_path = os.path.join(dir_path, target_dir_name)  # dir_path 내부에서 탐색

                    print(f"Target directory: {target_dir_path}")

                    if os.path.exists(target_dir_path) and os.path.isdir(target_dir_path):
                        target_file_path = os.path.join(target_dir_path, file_name)
                        shutil.move(file_path, target_file_path)
                        print(f"Moved {file_name} to {target_dir_path}")
                    else:
                        print(f"Directory {target_dir_name} does not exist in {dir_path} for {file_name}")

def main():
    base_dir = "./r_dirs_buffer_access_pt2"
    base_dir = os.path.abspath(base_dir)
    print(f"Base directory: {base_dir}")
    move_c_and_cpp_files_to_directory(base_dir)

if __name__ == "__main__":
    main()
