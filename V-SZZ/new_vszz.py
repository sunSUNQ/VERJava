#encoding=utf-8

import os
import sys
import shutil
import time
import subprocess
import linecache
import shutil
import hashlib
import re
import random
import math
import datetime

import operator
from antlr4 import *
from CLexer import CLexer
from CParser import CParser
import pickle as pickle

from termcolor import colored
from main_v4 import pre_parse, get_num_token_mapping, process_func_item, pre_process_remove_comments

import pydot
import json
import datetime

from dateutil import parser

dir_path = ''


# get target repo's cve list
def get_target_cve_list(target_repo):
    CVE_path = dir_path + 'diff_file/'
    CVE_list = []
    for parent, dirnames, filenames in os.walk(CVE_path):
        for filename in filenames:
            if target_repo == 'tomcat':
                if filename.split('_')[0] not in CVE_list and filename.find('jenkins')==-1 and filename.find('spring')==-1:
                    CVE_list.append(filename.split('_')[0])
            elif target_repo == 'jenkins':
                if filename.split('_')[1] not in CVE_list and filename.find('jenkins')!=-1:
                    CVE_list.append(filename.split('_')[1])
            elif target_repo.startswith('spring'):
                if filename.split('_')[1] not in CVE_list and filename.find(target_repo)!=-1:
                    CVE_list.append(filename.split('_')[1])
            elif target_repo == ('struts'):
                if filename.split('_')[1] not in CVE_list and filename.find(target_repo)!=-1:
                    CVE_list.append(filename.split('_')[1])
            elif target_repo == ('jackson-databind'):
                if filename.split('_')[1] not in CVE_list and filename.find(target_repo)!=-1:
                    CVE_list.append(filename.split('_')[1])
            elif target_repo == ('liferay-portal'):
                if filename.split('_')[1] not in CVE_list and filename.find(target_repo)!=-1:
                    CVE_list.append(filename.split('_')[1])
    return CVE_list


# get cve's commit
def get_CVE_commit(target_repo):
    CVE_list = get_target_cve_list(target_repo)
    commit_dict = {}
    for CVE_ID in CVE_list:
        patch_info_path = dir_path + 'patch_info/'
        #patch_info_list = []
        commit_dict[CVE_ID] = []
        for parent, dirnames, filenames in os.walk(patch_info_path):
            for filename in filenames:
                if filename.find(CVE_ID)!=-1:
                    #patch_info_list.append(os.path.join(parent,filename))
                    if filename.split('_')[-1].split('.')[0] not in commit_dict[CVE_ID]:
                        commit_dict[CVE_ID].append(filename.split('_')[-1].split('.')[0])
    return commit_dict


def get_parent_commit(target_repo, repo_dir):
    commit_dict = get_CVE_commit(target_repo)
    parent_commit_dict = {}
    for one in commit_dict:
        parent_commit_dict[one] = {}
        #print(one)
        for one_commit in commit_dict[one]:
            #print(one_commit)

            # git rev-list --parents -n 1 commit
            cmd = 'cd %s && git rev-list --parents -n 1 %s' % (repo_dir, one_commit)
            status, output = subprocess.getstatusoutput(cmd)
            parent_commit = output.split(' ')[1]
            parent_commit_dict[one][one_commit] = ''
            if parent_commit not in parent_commit_dict[one][one_commit]:
                parent_commit_dict[one][one_commit] = parent_commit
    return parent_commit_dict


def new_parse_diff(path_to_patch, CVE_ID):
    commit_id = path_to_patch.split('_')[-1].split('.')[0]

    res_add_index = {}
    res_add_list = {}
    res_delete_list = {}
    res_delete_index = {}

    patch_info_path = dir_path + 'patch_info/'
    patch_info_list = []
    for parent, dirnames, filenames in os.walk(patch_info_path):
        for filename in filenames:
            if filename.find(CVE_ID)!=-1 and filename.find(commit_id)!=-1:
                patch_info_list.append(os.path.join(parent,filename))
    #print(patch_info_list)
    for path_info in patch_info_list:
            with open(path_info, 'r') as f:
                path_json = json.loads(f.read())

            filename = path_json[0]['filename']
            res_add_index[filename] = []
            res_delete_index[filename] = []
            res_add_list[filename] = []
            res_delete_list[filename] = []
            removed_lines = path_json[0]['removed_line']
            added_line = path_json[0]['added_line']
            list_temp = []
            list_temp1 = []
            for oneline in removed_lines:
                temp_line = oneline['source_line_code'][1:].strip()
                if len(temp_line) > 0 and temp_line[-1] == '{':
                    temp_line = temp_line[:-1]
                list_temp1.append(temp_line)
                list_temp.append(oneline['source_line_num'])
            res_delete_index[filename].append(list_temp)
            res_delete_list[filename].append(list_temp1)
            list_temp = []
            list_temp1 = []
            for oneline in added_line:
                temp_line = oneline['target_line_code'][1:].strip()
                if len(temp_line) > 0 and temp_line[-1] == '{':
                    temp_line = temp_line[:-1]
                list_temp1.append(temp_line)
                list_temp.append(oneline['target_line_num'])
            res_add_index[filename].append(list_temp)
            res_add_list[filename].append(list_temp1)

    return res_delete_index,res_delete_list,res_add_index,res_add_list


def get_str(line):
    print(line)
    flag= re.search((r'[0-9]{4}\-[0-9]{2}\-[0-9]{2}\ [0-9]{2}\:[0-9]{2}\:[0-9]{2}.*'),line).group().find(')')
    string = re.search((r'[0-9]{4}\-[0-9]{2}\-[0-9]{2}\ [0-9]{2}\:[0-9]{2}\:[0-9]{2}.*'),line).group()[flag+1:]
    return string


def get_parcommit(fix_commit, repo_dir):
    command = 'cd %s && git checkout -f %s' % (repo_dir, fix_commit)
    print(command)
    os.system(command)
    tmp2 = 'C:/Users/sunqing/Desktop/vszz/vszz_output/tmp_data2'
    command = 'cd %s && git log > %s' % (repo_dir, tmp2)
    print(command)
    os.system(command)
    try:
        rf = open(tmp2, 'r')
        line1 = rf.readline()
    except:
        return 
    if line1.startswith('commit') and fix_commit in line1:
        line1=rf.readline()
        while line1:
            if line1.startswith('commit'):
                par_commit = line1.split(' ')[-1].replace('\n','')
                break
            line1=rf.readline()
        line1 = rf.readline()
    # command = 'cd /home/xy/vul_detect_src/src_repo/FFmpeg && git checkout master'
    # os.system(command)

    return par_commit


def get_filename(line):
    string = line.split(' ')[1]
    return string


def get_back_line_num(commit, string, filename, repo_dir, CVE_ID):
    # if '6ef14e5753e' in commit:
    #     return None
    tmp3 = '/vszz/vszz_output/tmp_data2'
    command = 'cd %s && git show %s > %s' % (repo_dir, commit, tmp3)
    print(command)
    os.system(command)
    res_delete,res_delete_list,res_add_index,res_add_list = new_parse_diff(tmp3, CVE_ID)
    if res_delete == 0:
        return None
    print(string)
    string = string.strip()
    print(string)
    if len(string) > 0 and string[-1] == '{':
        string = string[:-1]
    print(string)
    #print(res_add_index.keys())
    for filename_new in res_add_list.keys():
        if filename != filename_new:
            continue
        #print(res_add_list[filename])
        for i in range(len(res_add_list[filename])):
            if len(res_add_list[filename][i]):
                for j in range(len(res_add_list[filename][i])):
                    if res_add_list[filename][i][j] == string:
                        return res_add_index[filename][i][j]


def Levenshtein_Distance(str1, str2):
    """
    :param str1
    :param str2
    :return:
    """
    matrix = [[ i + j for j in range(len(str2) + 1)] for i in range(len(str1) + 1)]

    for i in range(1, len(str1)+1):
        for j in range(1, len(str2)+1):
            if(str1[i-1] == str2[j-1]):
                d = 0
            else:
                d = 1
            
            matrix[i][j] = min(matrix[i-1][j]+1, matrix[i][j-1]+1, matrix[i-1][j-1]+d)
    similarity = (1.00 - float(format(float(matrix[len(str1)][len(str2)])/float(max(len(str1), len(str2))),'.2f')))
    return similarity


def back_line(line, filename, repo_dir, CVE_ID):
    commit = line.split(' ')[0]
    str1 = get_str(line)
    par_commit = get_parcommit(commit, repo_dir)
    filename_new = get_filename(line)
    if filename_new.endswith('.c'):
        filename=filename_new
    print(filename)
    line_num = get_back_line_num(commit, str1, filename, repo_dir, CVE_ID)
    if line_num == None:
        return line
    print(line_num)
    command = 'cd %s && git checkout -f %s' % (repo_dir, par_commit)
    os.system(command)
    tmp_data = '/vszz/vszz_output/tmp_data'
    ####################### -1 
    command = 'cd %s && git blame -L %s,%s %s > %s' % (repo_dir, str(line_num-1), str(line_num-1), filename, tmp_data)
    print(command)
    os.system(command)
    rf = open(tmp_data, 'r')
    line1 = rf.readline()
    if len(line1) == 0:
        return line
    line1 = line1.replace('\n', '')
    str2 = get_str(line1)
    
    print(Levenshtein_Distance(str1, str2))
    if Levenshtein_Distance(str1, str2) < 0.75:
        return line
    else:
        return back_line(line1, filename, repo_dir, CVE_ID)



def vszz_step1(target_repo, specialCVE):
    repo_dir = target_repo 

    parent_commit_dict_file = '/vszz/vszz_output/'+target_repo+'_parent_commit_data.json'
    # with open(parent_commit_dict_file, 'r') as f:
    #     parent_commit_dict = json.loads(f.read())
    parent_commit_dict = get_parent_commit(target_repo, repo_dir)
    print(parent_commit_dict)
    with open(parent_commit_dict_file, 'w') as f:
        f.write(json.dumps(parent_commit_dict))


    for CVE_ID in parent_commit_dict:

        if CVE_ID.find(specialCVE)==-1:
            continue
        
        diff_path = dir_path + 'diff_file/'
        diff_list = []
        for parent, dirnames, filenames in os.walk(diff_path):
            for filename in filenames:
                if filename.find(CVE_ID)!=-1:
                    diff_list.append(os.path.join(parent,filename))
        #print(diff_list)
        for diff in diff_list:
            # if diff.find('ec08')==-1:
            #     continue
            fix_commit = diff.split('_')[-1].split('.')[0]
            try:
                test = parent_commit_dict[CVE_ID][fix_commit]
            except:
                print('error in get parent_commit!!!!!!!!!!!')
                continue

            #res_delete, res_delete_list, res_add_index, res_add_list = parse_diff(diff)
            res_delete, res_delete_list, res_add_index, res_add_list = new_parse_diff(diff, CVE_ID)
            #print(res_delete, res_delete_list, res_add_index, res_add_list)
            if res_delete == 0 :
                print('error in get diff_info!!!!!!!!!!!')
                continue
            add_num = 0
            delete_num = 0
            for filename in res_add_index:
                for i in res_add_index[filename]:
                    add_num+=len(i)
                for j in res_delete[filename]:
                    delete_num+=len(j)

            # if delete_num > 5 or delete_num == 0:
            #     print('error in delete line number!!!!!!!!!!!')
            #     continue
            if delete_num == 0:
                print('no delete num!!!!!!!!!!!')
                continue

            output_file = '/vszz/vszz_output/'+ target_repo +'_'+ CVE_ID +'_'+ diff.split('_')[-1].split('.')[0] + '.txt'
           
            w_f = open(output_file  ,'w')
            for filename in res_delete:
                for i in range(len(res_delete[filename])):
                    if len(res_delete[filename][i]):
                        for j in range(len(res_delete_list[filename][i])):

                            command = 'cd %s && git checkout -f %s' % (repo_dir, parent_commit_dict[CVE_ID][fix_commit])
                            print(command)  
                            os.system(command) #checkout到blame版本

                            tmp_data = '/vszz/vszz_output/tmp_data'
                            ######################### -1
                            command = 'cd %s && git blame -L %s,%s %s > %s' \
                                % (repo_dir, str(res_delete[filename][i][j]-1), str(res_delete[filename][i][j]-1), filename, tmp_data)
                            print(command)
                            status, output = subprocess.getstatusoutput(command)
                            if output.startswith('fatal'):
                                continue

                            rf = open(tmp_data, 'r')
                            line = rf.readline().replace('\n', '')
                            print(line)
                            backline = back_line(line, filename, repo_dir, CVE_ID)
                            w_f.write(backline+'\n')
                            print(backline)
                        
                        # print(res_delete_list[filename][i][j])
                        # print(res_delete[filename][i][j])
        
            
            command = 'cd %s && git checkout master' % (repo_dir)
            #print(res_delete,res_delete_list)
            print(command)

##############################################################################
# step two
##############################################################################

def lifetime_step2(rootdir,path, target_repo, specialCVE):
    #rootdir是待分析的数据（去重），path是待写入的数据
    w_path = rootdir + '/' + target_repo +'.txt'
    write_file = open(w_path,'w')
    list = os.listdir(rootdir)
    for i in list:
        if i.find(target_repo + '_')==-1:
            continue
        if i.find('.txt')==-1:
            continue
        if i.find(specialCVE)==-1:
            continue
        print(i)

        dict_fre={}
        dict_time = {}
        i1 = path + i

        file = open(i1,'r')
        line = file.readline()
        while line:
            key = line.split(' ')[0]
            line1 = line
            print(line1)
            temp = re.search((r'[0-9]{4}\-[0-9]{2}\-[0-9]{2}\ [0-9]{2}\:[0-9]{2}\:[0-9]{2}'),line1).group()
            #print(temp)
            if key not in dict_time:
                dict_time[key]=temp
            if key in dict_fre:
                
                dict_fre[key] += 1
            else:
                dict_fre[key] = 1
            line = file.readline()
        max=0
        res_dict={}
        for key in dict_fre.keys():
            if dict_fre[key]>max:
                temp_fre=key
                max = dict_fre[key]
        for key in dict_fre.keys():
            if dict_fre[key] == max:
                res_dict[key]= dict_time[key]
        try:
            res_dict[temp_fre] = dict_time[temp_fre]
        except:
            continue
        
        temp_key = i.split('.log')[0]
        res_dict1=sorted(res_dict.items(), key = lambda kv:(kv[1], kv[0]))
        print(res_dict1)

        write_file.write(temp_key+'\n'+res_dict1[0][0]+' '+res_dict1[0][1]+'\n')
        print(res_dict)
        print(dict_fre)



##############################################################################
# step three
##############################################################################

# get tags，then checkout to tag version and git log，get all commits
def get_git_log(target_repo):
    repo_dir = target_repo

    gittag = '/vszz/vszz_output/gittag_' + target_repo + '.txt'
    if not os.path.exists(gittag):
        cmd = 'cd %s && git tag > %s' % (repo_dir, gittag)
        subprocess.getstatusoutput(cmd)
        print('success git all tag')

    with open(gittag, 'r', encoding='utf-8') as f:
        file_content = f.read().split('\n')
    commit_list = ''
    for oneline in file_content:
        commit_repo = '/vszz/vszz_output/'+target_repo +'/'
        commit_file = commit_repo + oneline +'.txt'
        if not os.path.exists(commit_file):
            cmd = 'cd %s && git checkout -f %s' % (repo_dir, oneline.strip())
            print(cmd)
            os.system(cmd)
        
            if not os.path.exists(commit_repo):
                os.makedirs(commit_repo)
        
            cmd = 'cd %s && git log > %s' % (repo_dir, commit_file)
            os.system(cmd)
            print(cmd)
            print()






def in_version(string, gitlog_path):
    list = os.listdir(gitlog_path)
    result = []
    #print(list)
    for i in list:
        if 'rc' not in i:
            i1 = gitlog_path+'/'+i
            f = open(i1,'r')
            try:
                line = f.readline()
                while line:
                    if string in line:
                        result.append(i.split('.txt')[0])
                        break
                    line = f.readline()
            except:
                pass

    return result


def ifcherry(cve_num, target_repo):
    repo_dir = target_repo
    temp_file = '/vszz/vszz_output' + '/temp_git_show.txt'
    fixcommit=cve_num.split('_')[-1]
    flag=0
    command = 'cd %s && git show %s > %s' % (repo_dir, fixcommit, temp_file)
    print(command)
    os.system(command)
    from unidiff import PatchSet
    patches = PatchSet.from_filename(temp_file)
    
    patch_info = patches[0].patch_info
    
    return patch_info




def lifetime_step3(gitlog_path, read_path, target_repo, specialCVE):
    
    r_f = open(read_path,'r')
    line = r_f.readline()
    #w_f = open('C:/Users/sunqing/Desktop/vszz/vszz_output/Result_'+ target_repo +'.txt','w')
    while line:
        if 'CVE' in line:
            if specialCVE not in line:
                line = r_f.readline()
                line = r_f.readline()
                continue
            print(line)

            list2_key = line.replace('\n','').split('_')[-1].split('.')[0]
            
            #w_f.write(line)
            line = r_f.readline()
            list1_key = line.split(' ')[0]
            print('inducing_commit: ', list1_key)
            list1 = in_version(list1_key,gitlog_path)
            print(list1)
            #w_f.write('inducing_commit exists in :\n')
            #w_f.write(str(list1)+'\n')

            list2 = in_version(list2_key,gitlog_path)
            print('fixing_commit: ', list2_key)
            print(list2)
            #w_f.write('fixing_commit exists in :\n')
            #w_f.write(str(list2)+'\n')

            list2_temp = in_version(list2_key, gitlog_path)
            list2_1 = list2
            list2 = [i for i in list2_temp if i not in list2_1]
            for i in list2_1:
                list2.append(i)
            #print(list2)
            list1_not_in_list2 = [i for i in list1 if i not in list2]
            print('Result:')
            print(list1_not_in_list2)
            
            #w_f.write(str(list1_not_in_list2)+'\n')
        line = r_f.readline()




specialCVE = 'CVE-2017-1000362'
#target_repo = 'spring-framework'
#target_repo = 'spring-security'
target_repo = 'jenkins'
#target_repo = 'tomcat'
#target_repo = 'struts'
#target_repo = 'jackson-databind'
#target_repo = 'liferay-portal'

start = datetime.datetime.now()

vszz_step1(target_repo, specialCVE)

VSZZ_path = '/vszz/vszz_output'
output_path = VSZZ_path + '/'
lifetime_step2(VSZZ_path, output_path, target_repo, specialCVE)


gitlog_path = '/vszz/vszz_output/' + target_repo+ '/'
read_path = VSZZ_path +'/'+ target_repo +'.txt'
#get_git_log(target_repo)
lifetime_step3(gitlog_path,read_path, target_repo, specialCVE)

end = datetime.datetime.now()

try:
    print ((end-start).seconds)
    print (end-start)
except:
    print (end-start)
