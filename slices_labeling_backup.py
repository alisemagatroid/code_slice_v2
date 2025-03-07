""" 단일 파일만을 처리하기 위해 해당 버전을 backup 했다.
Returns:
    _type_: _description_
"""
import os
import json
import re
import glob
from pathlib import Path
import fnmatch
import warnings
from typing import Dict, Set, List, Tuple

# 현재 label_info_file, slices 파일은 동일한 디렉토리에 존재한다.
def find_label_info_file(slices_dir):
    directory_path = Path(slices_dir)
    
    for file in directory_path.glob("*_label_info.json"):  # 특정 패턴을 가진 파일만 순회
        if file.is_file():
            return str(file)
        
    print("해당하는 label_info 파일이 없습니다.")
    return None

# label_info 파일의 데이터를 추출하는 함수, 현재는 keyword 말고는 없다다
def extract_label_info(label_info_file) -> List[str]:
    
    with open(label_info_file, 'r', encoding='utf-8') as file:
        json_file = json.load(file)
        # label_info[0] = file['file_name']
        label_info = json_file['keyword'].strip()
        print(label_info)
        
    return label_info

# 이게 필요 없다.
def extract_slice_files(slices_dir) -> List[Path]:
    
    directory_path = Path(slices_dir)
    slice_json_files: List[Path] = []
    for slice_file in directory_path.glob("slices_*"):  
        if slice_file.is_file():
            slice_json_files.append(slice_file)
    return slice_json_files            


# fgets의 경우 label이 1로 잡히는 경우는 하나 뿐이다.(bad의 printIntLine이 수집된 스니펫 )
def process_label(label_info, slice_json_file, labeled_slices_dir):
    labeled_slices_dir = Path(labeled_slices_dir)

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
            if len(stripped_slice_line) < len(label_info):
                continue

            if label_info in stripped_slice_line:
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
        new_file_path = labeled_slices_dir / f"labeled_{slice_json_file}.json"
        with new_file_path.open('w', encoding='utf-8') as output_file:
            json.dump(slice_json, output_file, indent=4, ensure_ascii=False)
                        
                        
                
    



def labeling_slices(slices_dir, labeled_slices_dir):
    
    label_info_file = find_label_info_file(slices_dir)
    if label_info_file is None:
        return
     
    label_info = extract_label_info(label_info_file)
    
    # List로 나열된, slice_Dir 내부의 파일 이름이 List로 존재, Path에서 name만을 가져와 str값으로 존재한다.
    slice_json_files = extract_slice_files(slices_dir)
    
    process_label(label_info, slice_json_files, labeled_slices_dir)
    
    
        
        

                
                
        
        
if __name__ == '__main__':
    slices_dir = 'slices_Dir'
    labeled_slices_dir = 'label_testing'
    labeling_slices(slices_dir, labeled_slices_dir)