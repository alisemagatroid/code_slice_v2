# 해당 코드를 통해 파싱 -> 슬라이싱을 하기 위한 파일, 디렉토리를 세팅한다.
# 현재 해당 코드는 실행 전 취약점 유형이 정의되어있는 csv파일을 통해 디렉토리를 전부 생성한 상태에서 사용할 수 있다.

import os
import shutil
import re

# SARD_DIR: 해당 위치 하위에 디렉토리(export.json이 들어있는), 소스코드 파일들이 전부 옮겨진다.
# TARGET_DIR: SARD_DIR내에 있는 소스코드 파일, 디렉토리를 파일명을 정규식으로 비교해 알맞은 위치에옮기기 위한 디렉토리가 세팅되어있는 위치(여기서 파싱, 슬라이싱을 진행한다
SARD_DIR = r"D:\02_buffer_access"
TARGET_DIR = r"C:\Users\csw24\Projects\code_slice_v2\r_dirs"


# 불필요한 접미사(goodG2B, 21a ...)을 없애, 알맞은 위치에 이동하기 위한 세팅을 하는 함수
def clean_filename(name: str) -> str:
    base_name, ext = os.path.splitext(name)
    # 정규식 수정
    cleaned_name = re.sub(r'(_\d+(_[a-zA-Z0-9]+)*)$', '', base_name)
    return cleaned_name

# 파일 및 디렉토리 이동 함수
def move_files_and_dirs(sard_dir: str, target_dir: str):
    if not os.path.exists(sard_dir):
        print(f"❌ 오류: 원본 디렉토리가 존재하지 않습니다: {sard_dir}")
        return

    if not os.path.exists(target_dir):
        print(f"❌ 오류: 대상 디렉토리가 존재하지 않습니다: {target_dir}")
        return

    for cwe_folder in os.listdir(sard_dir):
        cwe_folder_path = os.path.join(sard_dir, cwe_folder)
        if not os.path.isdir(cwe_folder_path):
            continue  

        for root, dirs, files in os.walk(cwe_folder_path):
            # 디렉토리 이동
            for name in dirs:
                cleaned_name = clean_filename(name)
                target_subdir = os.path.join(target_dir, cleaned_name)

                if not os.path.exists(target_subdir):
                    print(f"⚠ 대상 디렉토리가 없어 이동하지 않음: {target_subdir}")
                    continue

                source_dir = os.path.join(root, name)
                if os.path.isdir(source_dir):
                    try:
                        shutil.move(source_dir, target_subdir)
                        print(f"📁 디렉토리 이동 완료: {source_dir} → {target_subdir}")
                    except Exception as e:
                        print(f"❌ 디렉토리 이동 실패: {source_dir} → {target_subdir}, 오류: {e}")

            # 파일 이동
            for name in files:
                if name.endswith((".h", ".bin", ".bat")):
                    continue

                cleaned_name = clean_filename(name)
                target_subdir = os.path.join(target_dir, cleaned_name)

                if not os.path.exists(target_subdir):
                    print(f"⚠ 대상 디렉토리가 없어 파일 이동하지 않음: {target_subdir}")
                    continue

                source_file = os.path.join(root, name)
                destination_file = os.path.join(target_subdir, name)

                if os.path.exists(destination_file):
                    print(f"⏩ 건너뜀: {name} (이미 존재)")
                    continue

                try:
                    shutil.move(source_file, destination_file)
                    print(f"📄 파일 이동 완료: {source_file} → {destination_file}")
                except Exception as e:
                    print(f"❌ 파일 이동 실패: {source_file} → {destination_file}, 오류: {e}")


# 실행
if __name__ == "__main__":
    move_files_and_dirs(SARD_DIR, TARGET_DIR)
