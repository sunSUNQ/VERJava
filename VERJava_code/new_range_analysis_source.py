#-*- coding:utf-8
import os
import json
import sys


# YOUR PATH
dir_path = ''


def find_focus_lines(file_content, patch_func):

    focus_line = []
    func_exist = False
    if patch_func != 'no':

        # handle special line in java, which one line split in two or more 
        file_content = file_content.replace(' \n',' ')
        file_content = file_content.replace(',\n',',').replace(')\n', ')').replace('\t', '').split('\n')
        
        # easy normalize
        normalize_file = []
        for line in file_content:
            normalize_file.append(line.strip())

        # find target function's body
        leftK = 0
        special_func_lines = []
        for oneline in normalize_file:

            if oneline.find(' '+patch_func+ '(')!=-1 and oneline.find('{')!=-1 and oneline.find('}')==-1:
                func_exist = True
                leftK += 1
                special_func_lines.append(oneline)
            elif leftK != 0:
                special_func_lines.append(oneline)
                if oneline.find('{')!=-1:
                    leftK += 1
                if oneline.find('}')!=-1:
                    leftK -= 1

        for one_line in special_func_lines:
            one_line = one_line.replace(')    ', ')\n').replace(',    ', ',\n')
            if one_line.find('\n')!=-1:
                for one in one_line.split('\n'):
                    focus_line.append(one.strip())
                
            else:
                focus_line.append(one_line.strip())
            
    else:
        file_content = file_content.split('\n')
        # easy normalize
        normalize_file = []
        for line in file_content:
            normalize_file.append(line.strip())
        focus_line = normalize_file

    return focus_line, func_exist



def calculate_new_func_or_not(patch_func, file_content, add_line, focus_line):

    new_func = False
    file_content = file_content.replace(',\n',',').replace(')\n', ' )').replace('\t', '').split('\n')
    new_add_line = []
    for one_line in add_line:
        if one_line not in new_add_line:
            new_add_line.append(one_line)
    
    # easy normalize
    normalize_file = []
    for line in file_content:
        normalize_file.append(line.strip())
    
    if patch_func == 'no':
        focus_line = normalize_file
    #     if len(new_add_line) / len(normalize_file) >= 0.9:
    #         new_func = True

    new_focus_line = []
    for one in focus_line:
        if one != '' and one.strip() != '}':
            new_focus_line.append(one.strip())
    if new_focus_line == []:
        return False
    if new_focus_line[0].startswith('@'):
        del new_focus_line[0]

    if len(new_focus_line)!=0 and len(new_add_line) / len(new_focus_line) >= 0.9 :
        new_func = True

    return new_func



def calculate_add_line_exist(add_line, focus_line):

    patch_exist = False
    total_add_num = 0
    exists_add_num = 0
    new_add_line = []
    for one_line in add_line:
        if one_line not in new_add_line:
            new_add_line.append(one_line)
    
    if new_add_line == []:
        return

    no_found = []
    for one_line in new_add_line:
        total_add_num += 1
        Find = False
        if one_line['target_line_code'] in focus_line:
            Find = True
            exists_add_num += 1
        else:
            for one in focus_line:
                if one.find(one_line['target_line_code'].strip())!=-1:
                    exists_add_num += 1
                    Find = True
            if Find == False:
                no_found.append(one_line['target_line_code'])


    # Tadd = 0.9
    if exists_add_num == total_add_num:
        patch_exist = True
    elif exists_add_num / total_add_num >= 0.9:
        patch_exist = True
    #print("add: ", exists_add_num / total_add_num)

    return patch_exist



def calculate_remove_line_exist(remove_line, focus_line):

    vul_exist = False
    total_remove_num = 0
    exists_remove_num = 0
    new_remove_line = []
    for one_line in remove_line:
        if one_line not in new_remove_line:
            new_remove_line.append(one_line)
    
    if new_remove_line == []:
        return 

    no_found = []
    for one_line in new_remove_line:
        Find = False
        total_remove_num += 1
        if one_line['source_line_code'] in focus_line:
            exists_remove_num += 1
            Find = True
        else:
            for one in focus_line:
                if one.find(one_line['source_line_code'].strip())!=-1:
                    exists_remove_num += 1
                    Find = True
            if Find == False:
                no_found.append(one_line['source_line_code'])
    
    # Tdel = 1
    if exists_remove_num == total_remove_num:
        vul_exist = True
    elif exists_remove_num / total_remove_num >= 1:
        vul_exist = True
    #print("removed: ", exists_remove_num / total_remove_num)
    
    return vul_exist




def analysis_patch_exist_version(path_json, target_repo, CVE_ID, zip_list):

    patch_func = path_json[0]['patch_func']

    # generate full path
    if target_repo == 'tomcat':
        if path_json[0]['filename'].find('/java')!=-1:
            file_name  = '/java' + path_json[0]['filename'].split('/java')[1]
        else:
            file_name  = '/java/org' + path_json[0]['filename'].split('/org')[1]
    else:
        file_name  = path_json[0]['filename']
    
    add_line = path_json[0]['added_line']
    remove_line = path_json[0]['removed_line']

    result_version = []
    new_func = False
    file_or_func_no_exist = []


    for one_version_file in zip_list:
        patch_file = one_version_file +'/'+ file_name

        func_exist = False
        if target_repo == 'tomcat':
            this_version = one_version_file.split('tomcat-')[1]
        else:
            this_version = one_version_file.split(target_repo+'-')[1]


        if os.path.exists(patch_file):

            with open(patch_file, 'r', encoding='utf-8') as f:
                file_content = f.read()

            # find patch_func's lines, and if function exist in target version 
            focus_line, func_exist = find_focus_lines(file_content, patch_func)

            # calculate if patch's func is a new func
            new_func_flag = calculate_new_func_or_not(patch_func, file_content, add_line, focus_line)
            
            # for one patch count one flag 
            if not new_func:
                if new_func_flag:
                    new_func = True

            # calculate result version
            patch_exist = calculate_add_line_exist(add_line, focus_line)
            vul_exist = calculate_remove_line_exist(remove_line, focus_line)

            #print(patch_exist, vul_exist)

            if patch_exist == False and vul_exist == True:
                result_version.append(this_version)
            elif patch_exist == None and vul_exist == True:
                result_version.append(this_version)
            elif patch_exist == False and vul_exist == None:
                result_version.append(this_version)

            # special condition
            if func_exist == False and patch_func != 'no':
                file_or_func_no_exist.append(this_version)
        else:
            file_or_func_no_exist.append(this_version)

    return result_version, file_or_func_no_exist, new_func


def range_analysis(CVE_ID, target_repo, DEBUG):
    
    #### get all versions we have
    #allversion_list = ['6.0.16', '7.0.0']
    #src_list = ['YOUR_PATH/VERJava_code/source_code/tomcat-6.0.16']
    source_code_path = dir_path + 'source_code/'
    dirname_list = os.listdir(source_code_path)
    
    allversion_list = []
    src_list = []

    for dirname in dirname_list:
        if dirname.find(target_repo)!=-1:
            allversion_list.append(dirname.split('/')[-1].split('-')[1])
            src_list.append(os.path.join(source_code_path, dirname))


    if DEBUG:
        print()
        print('Handling CVE: ', CVE_ID)

    #########
    patch_info_path = dir_path + 'patch_info/'
    #########
    patch_info_list = []
    for parent, dirnames, filenames in os.walk(patch_info_path):
        for filename in filenames:
            if filename.find(CVE_ID)!=-1 and filename.find(target_repo)!=-1:
                patch_info_list.append(os.path.join(parent,filename))

    # different branch split
    # {'1065939',...}
    version_list = []
    for one in patch_info_list:
        version_id = one.split('_')[-1].split('.json')[0]
        if version_id not in version_list:
            version_list.append(version_id)
        
    new_func_flag = {}
    no_exist = {}
    affect_version_list = {}
    for path_info in patch_info_list:

        with open(path_info, 'r') as f:
            path_json = json.loads(f.read())

        patch_name = path_info.split('/')[-1]
        if DEBUG:
            print('Handling patch: ', patch_name)

        result_version, file_or_func_no_exist, new_func = analysis_patch_exist_version(path_json, target_repo, CVE_ID, src_list)
        new_func_flag[path_info.split('/')[-1]] = new_func
        no_exist[path_info.split('/')[-1]] = file_or_func_no_exist
        if DEBUG:
            print('Vulnerable versions: ', result_version)
            print()

        affect_version_list[path_info.split('/')[-1]] = result_version


    # different branch handle 
    big_result = {}
    for one_version in version_list:

        total_num = 0
        result = []
        version_num_list = {}
        for o_version in allversion_list:
            version_num_list[o_version] = 0

        for path_info in patch_info_list:
            if path_info.find(one_version)==-1:
                continue

            if len(affect_version_list[path_info.split('/')[-1]]) != 0:
                total_num += 1
            for o_version in allversion_list:
                if not new_func_flag[path_info.split('/')[-1]]:
                    if o_version in no_exist[path_info.split('/')[-1]]:
                        continue
                if o_version in affect_version_list[path_info.split('/')[-1]]:
                    version_num_list[o_version] += 1

        for one in version_num_list:
            reduce_total_num = total_num
            if reduce_total_num == 0:
                continue
            # if some file or func do not exist, reduce the total_num
            for path_info in patch_info_list:
                if path_info.find(one_version)==-1:
                        continue
                if len(affect_version_list[path_info.split('/')[-1]]) == 0:
                    continue
                if not new_func_flag[path_info.split('/')[-1]]:
                    if one in no_exist[path_info.split('/')[-1]]:
                        reduce_total_num = reduce_total_num-1
            if reduce_total_num == 0:
                continue

            # calculation two and T=0.8
            if version_num_list[one] >= int(reduce_total_num*0.8) and version_num_list[one] != 0 and reduce_total_num > 3:
                result.append(one)
            elif reduce_total_num - version_num_list[one] <= 1 and reduce_total_num > 3:
                result.append(one)
            elif reduce_total_num <= 3 and version_num_list[one] == reduce_total_num and reduce_total_num >= total_num*0.5:
                result.append(one)


        big_result[one_version] = result

    # different branch result do ∪
    final_result = []
    for key in big_result:
        if final_result == []:
            final_result = big_result[key]
        else:
            final_result = set(final_result) | set(big_result[key])
            
        
    final_result = list(final_result)
    final_result.sort(key=None, reverse=False)
    if DEBUG:
        print(CVE_ID, 'Exist in version : ')
        print(final_result)

        

if __name__ == '__main__' :

    # repo_name = sys.argv[1]
    # cve_id = sys.argv[2]
    repo_name = 'tomcat'
    cve_id = 'CVE-2008-2938'

    DEBUG = True

    range_analysis(cve_id, repo_name, DEBUG)
