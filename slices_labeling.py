
"""
    하나에 대해서, 성공적으로 labeling이 되는 것을 확인, slices_dirs에 있는 .json파일들에 대하여 순회 
    
    현재 여러개의 파일을 순차적으로 레이블링해서 옮길 예정이지만, label_info 파일이 대응되는 만큼 있어야, 가능하다.
    아니면, 하나의 label_info 파일을 여러번 조회해서, 뭐... 파일명 대로 분류(파일명은 취약점 유형별로 네이밍 되어 있음음)
    
    건오 주임님께서 제작하신 label_info 파일 참고해서 제작 ㅇㅇㅇ
    
    이제 여기다 csv파일로 바로 적용 - convert_label_info_file 참조조
"""

import os
import csv
import json
from pathlib import Path
import fnmatch
import re
from typing import Dict, Set, List, Tuple



# 현재 label_info_file, slices 파일은 동일한 디렉토리에 존재한다.
def find_label_info_file(slices_dir):
    directory_path = Path(slices_dir)
    
    for file in directory_path.glob("*_label_info.csv"):  # 특정 패턴을 가진 파일만 순회
        if file.is_file():
            return str(file)
        
    print("해당하는 label_info 파일이 없습니다.")
    return None

# label_info.json 파일은
# 그리고, file_info 파일을 .json 파일에 맞게 세팅해야 여러개의 파일을 레이블링하고 옮길 수 있다.
# 현재는 csv 상으로 label_info 파일이 존재
# def extract_label_info(label_info_file) -> Dict[str, str]:
    
#     label_info = {}
    
#     with open(label_info_file, 'r', encoding='utf-8') as file:
#         json_file = json.load(file)
        
#         for info in json_file:
#             file_name = info['file_name']
#             keyword = info['keyword']
            
#             if file_name: 
#                 label_info[file_name] = keyword
            
#         print(label_info)
        
#     return label_info


# 레이블링 정보가 포함된 csv 파일을 받아와서, label_info에 Dict 형태로 가져온다.
def extract_label_info_csv(label_info_file: str) -> Dict[str, str]:
    label_info = {}

    with open(label_info_file, "r", encoding="utf-8") as infile:
        reader = csv.reader(infile)
        header = next(reader)  # 첫 번째 줄(헤더) 건너뛰기
        
        # 해당 row의 0은 filename, 1은 bad_keyword
        for row in reader:
            if len(row) < 2:
                continue  # 데이터가 부족한 경우 건너뛰기

            file_name = row[0].strip()
            bad_keyword = row[1].strip()

            if file_name and bad_keyword:  # 빈 값 체크
                label_info[file_name] = bad_keyword

    return label_info


            
# slices_dirs에 있는 모든 슬라이스 파일들을 List로 받아온다. 
def extract_slice_file(slices_dir) -> List[Path]:
    
    directory_path = Path(slices_dir)
    slice_json_files: List[Path] = []
    
    for slice_file in directory_path.glob("slices_*"):
        if slice_file.is_file():
            slice_json_files.append(slice_file)
    return slice_json_files   

# fgets의 경우 label이 1로 잡히는 경우는 하나 뿐이다.(bad의 printIntLine이 수집된 스니펫 )

# slice_json_file은 Path 값으로 날라온다.
def extract_slice_file_name(slice_json_file):
    
    file_name_pattern = r'slices_(.*)\.json'
    slice_file_name =  slice_json_file.name
    
    match = re.match(file_name_pattern, slice_file_name)
    
    if match:
        return match.group(1)
    else :
        return None
    
def find_label_keyword(label_info, slice_file_name):
    return label_info.get(slice_file_name, None)

def process_label(label_info, slice_json_file, labeled_slices_dir):
    labeled_slices_dir = Path(labeled_slices_dir)
    
    
    #label_info 파일과 비교하기 위해 앞의 slices_와 파일 확장자 .json을 제거하기위한 로직 필요
    # 해당 파일의 slice, .json을 제외한 파일 값을 가져오고 label_info 상의
    slice_file_name = extract_slice_file_name(slice_json_file)

    bad_keyword = find_label_keyword(label_info, slice_file_name)
    
    if bad_keyword is not None: 
        with slice_json_file.open('r', encoding='utf-8') as file:
            slice_json = json.load(file)

            snippets = slice_json["snippets"]
            modified = False  # 변경 여부 추적
            vul_snippet_counter = 0

            for snippet in snippets:
                parent_method = snippet['parent_method']

                if 'bad' not in parent_method:
                    snippet["label"] = 0
                    modified = True
                    continue  # 'bad'가 없는 경우 다음 snippet으로 넘어감

                slices = snippet['slices']
                found = False  # label_info를 찾았는지 확인

                for slice_line in slices:
                    stripped_slice_line = slice_line.strip()

                    # keyword가 존재하는 슬라이스 라인이, keyword보다 짧으면 건너뜀
                    #
                    slice_line_len = len(stripped_slice_line)
                    bad_keyword_len = len(bad_keyword)
                    
                    if slice_line_len < bad_keyword_len:
                        continue

                    if bad_keyword in stripped_slice_line:
                        snippet["label"] = 1  # 한번이라도 찾으면 label = 1
                        found = True
                        vul_snippet_counter += 1
                        break  # 더 이상 검사할 필요 없음

                # 모든 slices를 검사했지만 label_info를 찾지 못한 경우
                if not found:
                    snippet["label"] = 0

                modified = True  # 변경됨을 표시

            slice_json["vulnerable_snippets_info"] = vul_snippet_counter

            # JSON 파일 업데이트 (변경 사항이 있는 경우)
            if modified:
                new_file_path = labeled_slices_dir / f"labeled_{slice_json_file.stem}.json"
                with new_file_path.open('w', encoding='utf-8') as output_file:
                    json.dump(slice_json, output_file, indent=4, ensure_ascii=False)
                        
                                
def labeling_slices(slices_dir, labeled_slices_dir):
    
    #slices_dirs 내에 csv 파일을 찾고 가져온다.
    label_info_file = find_label_info_file(slices_dir)
    if label_info_file is None:
        return
     
    # label_info도 매번 찾는게 아니라, 한번에 데이터를 List화 한 후, 저기서 매치되는 값을 찾는다.
    label_info = extract_label_info_csv(label_info_file)
    
    # List로 나열된, slice_Dir 내부의 파일 이름이 List로 존재, Path에서 name만을 가져와 str값으로 존재한다.
    slice_json_files = extract_slice_file(slices_dir)
    
    # 리스트로 받아온 만큼 반복
    for slice_json_file in slice_json_files:
        process_label(label_info, slice_json_file, labeled_slices_dir)
        

if __name__ == '__main__':
    slices_dir = 'slices_dirs'
    labeled_slices_dir = 'label_testing'
    labeling_slices(slices_dir, labeled_slices_dir)