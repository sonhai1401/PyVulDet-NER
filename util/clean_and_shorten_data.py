# This script is part of a larger research project shown at https://github.com/mmeberg/PyVulDet-NER

import pandas as pd
import os
import time
import json
import re
import pickle
import math

def tag_vulparts(token_list, mode, tester):
    ner_tag_dict_nums = {'rce':[1, 2],
                         'oob':[3, 4],
                         'xss':[5, 6],
                         'sql':[7, 8],
                         'iiv':[9,10],
                         'pat':[11,12],
                        }

    num1 = ner_tag_dict_nums[mode][0]
    num2 = ner_tag_dict_nums[mode][1]

    ner_tags = []
    for idx, tok in enumerate(token_list):
        if idx == tester[0]:
            ner_tags.append(num1)
        elif idx in range(tester[0], tester[1]+1):
            ner_tags.append(num2)
        else:
            ner_tags.append(0)

    return ner_tags

def getneutralText(text):
    newtext = ''
    lines = text.split("\n")
    for line in lines:
        line = line.strip()
        if len(line) > 0:
            if line[0] == "-":
                continue
            elif line[0] == "+":
                newtext = newtext + '\n' + line[1:]
            else:
                newtext = newtext + '\n' + line
    return newtext

def extract_vulparts_from_diff(diff_text):
    """
    Tạo cột 'vulparts' thủ công từ diff gốc, lấy các dòng bị xóa (bắt đầu bằng '-')
    """
    if not diff_text:
        return []
    lines = diff_text.split('\n')
    bad_lines = []
    for line in lines:
        line = line.strip()
        # Bỏ qua dòng diff header bắt đầu bằng '---'
        if line.startswith('-') and not line.startswith('---'):
            bad_lines.append(line[1:].strip())
    return bad_lines

def shorten_data_with_windows_v2(infodict):
    '''
    taking the really large samples and making them smaller
    '''
    new_info = []
    text = infodict['text']
    new_size = 3000

    if 'cdef ' in text[:50]:
        return []
    if len(text) > 500000:
        return []
    # neutral parts
    if infodict.type == 'gp':
        if len(text) >= new_size:
            chunk_start = 0
            chunk_size = new_size
            breaks = re.finditer(r"[\n]|$|[)]|[}]|[]]",text)
            break_ids = [m.end(0) for m in breaks]
            break_ids_to_use = []
            for i in range(math.ceil(len(text)/new_size)):
                if i == 0:
                    break_id = [m for m in break_ids if m <=new_size][-1]
                    chunk_start = 0
                else:
                    break_id = [m for m in break_ids if m >= break_ids_to_use[i-1] and m <= break_ids_to_use[i-1]+new_size][-1]
                    chunk_start = break_ids_to_use[i-1]
                break_ids_to_use.append(break_id)
                chunk = [chunk_start, break_id]
                new_tokens = text[chunk[0]:chunk[1]]
                new_info.append(new_tokens)

        else:
        ## If there are not more than 512 tokens
            new_tokens = text
            new_info.append(new_tokens)

    else: #vulparts
        bp_len = infodict['bp_len']
        bp_index = infodict['bp_index']+1
        bp_end = bp_index+bp_len-1
        tag_indeces = [bp_index, bp_end+1]

        # If there are more than 512 tokens
        if len(text) >= new_size:
            # If the indeces start and stop before 512, cut the list to 512
            if tag_indeces[0] < new_size and tag_indeces[1] <= new_size:
                breaks = re.finditer(r"[\n]|$|[)]|[}]|[]]",text)
                break_ids = [m.end(0) for m in breaks]
                break_id_to_use = [m for m in break_ids if m <= new_size][-1]
                new_tokens = text[:break_id_to_use]
                new_info.append(new_tokens)
            elif bp_len <= new_size:
                breaks = re.finditer(r"[\n]|$|[)]|[}]|[]]",text)
                break_ids = [m.end(0) for m in breaks]
                break_id_to_use1 = [m for m in break_ids if m <= bp_index][-1]
                break_id_to_use2 = [m for m in break_ids if m >= break_id_to_use1 and m <= break_id_to_use1+new_size][-1]
                new_tokens = text[break_id_to_use1:break_id_to_use2]
                new_info.append(new_tokens)
            else:
                breaks = re.finditer(r"[\n]|$|[)]|[}]|[]]",text)
                break_ids = [m.end(0) for m in breaks]
                break_ids_to_use = []
                for i in range(math.ceil(len(text)/new_size)):
                    if i == 0:
                        break_id = [m for m in break_ids if m <=new_size][-1]
                        chunk_start = 0
                    else:
                        break_id = [m for m in break_ids if m >= break_ids_to_use[i-1] and m <= break_ids_to_use[i-1]+new_size][-1]
                        chunk_start = break_ids_to_use[i-1]
                break_ids_to_use.append(break_id)
                chunk = [chunk_start, break_id]
                new_tokens = text[chunk[0]:chunk[1]]
                new_info.append(new_tokens)

        else:
            ## If there are not more than 512 tokens
            new_tokens = text
            new_info.append(new_tokens)

    return new_info
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~


file_list = list(os.listdir('C:/Users/ACER/Downloads/do an/PyVulDet-NER-demo/improve/Data\\'))

all_data = []

for file in file_list:
    with open('C:/Users/ACER/Downloads/do an/PyVulDet-NER-demo/improve/Data\\'+file, 'r', encoding='utf-8') as infile:
        data = json.load(infile)
    if len(data) != 0:
        print(file, len(data))
        for info in data:
            # Tạo vulparts thủ công dựa trên orig_diff
            info['vulparts'] = extract_vulparts_from_diff(info.get('orig_diff', ''))
            all_data.append(info)
print(len(all_data))


df_all = pd.DataFrame(all_data)

df_new = df_all.copy()

required_cols = ['cwetype', 'commit', 'neutralparts', 'vulparts','orig_diff','orig_txt']
existing_cols = [col for col in required_cols if col in df_new.columns]
print("Columns used for processing:", existing_cols)

df_new = df_new[existing_cols]

start_time = time.time()
neutraltext = [getneutralText(x) for x in df_new.orig_diff]
print("Elapsed time for neutral text extraction:", time.time() - start_time, "seconds")

## VUL PARTS ##
df_bp = df_new.copy()
df_bp = df_bp[['cwetype', 'vulparts', 'orig_txt']]

# find all single comments and replace with nothing
bp_text_without_single_comments = [re.sub('(#.*)', '', str(x)) for x in df_bp.orig_txt.tolist()]
# find all comment blocks and replace with nothing - double quotes
bp_text_without_comment_blocks1 = [re.sub(r'(["])\1\1(.*?)\1{3}', '', str(x), flags = re.DOTALL) for x in bp_text_without_single_comments]
# find all comment blocks and replace with nothing - single quotes
bp_text_without_comment_blocks2 = [re.sub(r"(['])\1\1(.*?)\1{3}", ' ', str(x), flags = re.DOTALL) for x in bp_text_without_comment_blocks1]

df_bp['text'] = bp_text_without_comment_blocks2
df_bp = df_bp.drop(columns =['orig_txt'])
df_bp['type'] = ['bp']*len(df_bp)

df_bp = df_bp.rename(columns = {'vulparts':'parts'})
df = df_bp.copy()

#saving just in case
with open('clean_dataset.pickle', 'wb') as output:
    pickle.dump(df, output)
    
df = df.explode('parts')
df = df.fillna('')
df = df[df.text != '']
df = df[df.parts != '']
df = df[df.parts.str.len() > 1]
df['len_set_parts'] = df['parts'].apply(lambda x: len(set(x.strip())))
df = df[df.len_set_parts > 3 ]

cwe = []
for x in zip(df.type.tolist(), df.cwetype.tolist()):
    if x[0] == 'gp':
        cwe.append('neutral')
    else:
        cwe.append(x[1])
df['cwetype'] = cwe

print(df.cwetype.value_counts())

df['bp_len'] = [len(x) for x in df.parts]

def find_partstart(row):
    if row.type == 'bp':
        bp_index = row['text'].find(row['parts'])
    else:
        bp_index = ''
    return bp_index

start_time = time.time()
df['bp_index'] = df.apply(find_partstart, axis =1)
print("Elapsed time for finding part start:", time.time() - start_time, "seconds")

start_time = time.time()
results = []
for x in range(0, len(df), 50000):
    print(len(df)-x)
    df_test = df.iloc[x: x+50000]
    results.append(df_test.apply(shorten_data_with_windows_v2, axis =1))
print("Elapsed time for shortening data:", time.time() - start_time, "seconds")

short_results = [i for info in results for i in info]
df['short_text'] = short_results

df = df.explode('short_text')
df = df.reset_index(drop=True)

df = df[df.short_text !='']
df = df.dropna(subset=['short_text'])
df = df[df.parts != '']
df = df[df.parts.str.len() >= 3]
df = df.reset_index(drop=True)

df['short_text2'] = [x.strip() for x in df.short_text.to_list()]

df = df.drop(columns = ['short_text'])
df = df.rename(columns = {'short_text2':'short_text'})

#saving
with open('clean_dataset_short.pickle', 'wb') as output:
    pickle.dump(df, output)
