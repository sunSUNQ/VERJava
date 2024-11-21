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
                if filename.split('_')[0] not in CVE_list and filename.split('_')[0].find('CVE')!=-1:
                    CVE_list.append(filename.split('_')[0])
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

            # if not one_commit.startswith('10377'):
            #     continue
            # print(commit_dict[one])
            # print(one_commit)

            # git rev-list --parents -n 1 commit
            #cmd = 'cd %s && git rev-list --parents -n 1 %s' % (repo_dir, one_commit)
            #status, output = subprocess.getstatusoutput(cmd)
            try:
                parent_commit = int(one_commit) -1
            except:
                continue
            parent_commit_dict[one][one_commit] = ''
            if str(parent_commit) not in parent_commit_dict[one][one_commit]:
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
                list_temp.append(oneline['source_line_num']-1)
            res_delete_index[filename].append(list_temp)
            res_delete_list[filename].append(list_temp1)
            list_temp = []
            list_temp1 = []
            for oneline in added_line:
                temp_line = oneline['target_line_code'][1:].strip()
                if len(temp_line) > 0 and temp_line[-1] == '{':
                    temp_line = temp_line[:-1]
                list_temp1.append(temp_line)
                list_temp.append(oneline['target_line_num']-1)
            res_add_index[filename].append(list_temp)
            res_add_list[filename].append(list_temp1)

    return res_delete_index,res_delete_list,res_add_index,res_add_list


def get_str(line):
    print(line)
    flag= re.search((r'[0-9]{4}\-[0-9]{2}\-[0-9]{2}\ [0-9]{2}\:[0-9]{2}\:[0-9]{2}.*'),line).group().find(')')
    string = re.search((r'[0-9]{4}\-[0-9]{2}\-[0-9]{2}\ [0-9]{2}\:[0-9]{2}\:[0-9]{2}.*'),line).group()[flag+1:]
    return string


def get_parcommit(fix_commit, repo_dir):
    command = 'cd %s && svn checkout -f %s' % (repo_dir, fix_commit)
    print(command)
    os.system(command)
    tmp2 = '/vszz/vszz_output/tmp_data2'
    command = 'cd %s && svn log > %s' % (repo_dir, tmp2)
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
    command = 'cd %s && svn commit %s > %s' % (repo_dir, commit, tmp3)
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
    计算字符串 str1 和 str2 的编辑距离
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


def back_line(line, filename, repo_dir, CVE_ID, res_delete):
    commit_id = line.split(' ')[0]
    #str1 = get_str(line)
    par_commit = str(int(commit_id) - 1)
    # filename_new = get_filename(line)
    # if filename_new.endswith('.c'):
    #     filename=filename_new
    # print(filename)
    # line_num = get_back_line_num(commit, line, filename, repo_dir, CVE_ID)
    # if line_num == None:
    #     return line
    # print(line_num)
    command = 'cd %s && svn update -r %s %s' % (repo_dir, par_commit, filename)
    os.system(command)
    print(command)

    tmp_data = '/vszz/vszz_output/tmp_data'
    command = 'cd %s && svn blame -r %s %s > %s' \
        % (repo_dir, commit_id, filename, tmp_data)
    print(command)
    os.system(command)

    rf = open(tmp_data, 'r')
    lines = rf.readlines()
    commit_id2 = ''
    for one_line in lines:
        if res_delete in one_line:
            print(one_line)
            if one_line.find(' remm ')!=-1:
                print(one_line.split(' remm ')[0].strip())
                commit_id2 = one_line.split(' remm ')[0].strip()
            elif one_line.find(' mturk ')!=-1:
                print(one_line.split(' mturk ')[0].strip())
                line = one_line.split(' mturk ')[0].strip()
            else:
                exit()
    
    if commit_id2 == commit_id:
        return line
    
    print(Levenshtein_Distance(commit_id, commit_id2))
    if Levenshtein_Distance(commit_id, commit_id2) < 0.75:
        return line
    else:
        return back_line(commit_id2, filename, repo_dir, CVE_ID, res_delete)



def vszz_step1(target_repo, specialCVE):
    repo_dir = 'C:/tomcat-checkout/tomcat/'#项目所在目录

    parent_commit_dict_file = '/vszz/vszz_output/'+target_repo+'_svn_parent_commit_data.json'
    with open(parent_commit_dict_file, 'r') as f:
        parent_commit_dict = json.loads(f.read())
    # parent_commit_dict = get_parent_commit(target_repo, repo_dir)
    # print(parent_commit_dict)
    # with open(parent_commit_dict_file, 'w') as f:
    #     f.write(json.dumps(parent_commit_dict))

    log_file = '/vszz/vszz_output/svn_tomcat_tag2commit.json'
    with open(log_file, 'r') as f:
        commit_json = json.loads(f.read())
    for CVE_ID in parent_commit_dict:

        if CVE_ID.find(specialCVE)==-1:
            continue
        print('\n')
        print(CVE_ID)
        diff_path = dir_path + 'diff_file/'
        diff_list = []
        for parent, dirnames, filenames in os.walk(diff_path):
            for filename in filenames:
                if filename.find(CVE_ID)!=-1:
                    diff_list.append(os.path.join(parent,filename))
        #print(diff_list)
        for diff in diff_list:
            output_file = '/vszz/vszz_output/'+ target_repo +'_'+ CVE_ID +'_'+ diff.split('_')[-1].split('.')[0] + '.txt'
            # if os.path.isfile(output_file):
            #     with open(output_file, 'r') as f:
            #         file = f.read()
            #         print(file)
            #         lines = file.split('\n')
            #     small_commit = 0
            #     for oneline in lines:
            #         try:
            #             inducing_commit = int(oneline.split('\t')[0])
            #         except:
            #             continue
            #         if inducing_commit < small_commit and small_commit != 0:
            #             small_commit = inducing_commit
            #         elif small_commit == 0:
            #             small_commit = inducing_commit
            #     if small_commit == 0:
            #         continue
            #     print(small_commit)

            #     small_list = []
            #     for one_tag in commit_json:
            #         if int(one_tag['revision']) <= int(small_commit):
            #             if one_tag['tag'] not in result_list:
            #                 small_list.append(one_tag['tag'])
            #     print(small_list)
            #     continue

            fix_commit = diff.split('_')[-1].split('.')[0]
            # print(parent_commit_dict[CVE_ID])
            # print(fix_commit)
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
            print("delete_num: ", delete_num)
            # if delete_num > 5 :
            #     print('more delete line number!!!!!!!!!!!')
            #     continue
            if delete_num == 0:
                print('no delete line number!!!!!!!!!!!')
                continue

            w_f = open(output_file  ,'w')
            for filename in res_delete:
                if filename.find('5.5.x')!=-1:
                    continue
                new_filename = filename
                #new_filename = 'archive/tc6.0.x' + filename.split('archive')[1]
                # if filename.find('6.')==-1:
                #     if filename.find('8.')==-1:
                #         if filename.find('7.0')!=-1:
                #             new_filename = filename

                for i in range(len(res_delete[filename])):
                    if len(res_delete[filename][i]):
                        for j in range(len(res_delete_list[filename][i])):

                            command = 'cd %s && svn update -r %s %s' % (repo_dir, parent_commit_dict[CVE_ID][fix_commit], new_filename)
                            print(command)  
                            os.system(command)

                            tmp_data = '/vszz/vszz_output/tmp_data'
                            command = 'cd %s && svn blame -r %s %s > %s' \
                                % (repo_dir, parent_commit_dict[CVE_ID][fix_commit], new_filename, tmp_data)
                            print(command)
                            
                            #continue
                            status, output = subprocess.getstatusoutput(command)
                            if output.startswith('fatal') or output.startswith('svn: warning:'):
                                continue

                            rf = open(tmp_data, 'r')
                            lines = rf.readlines()
                            print(lines)
                            print(res_delete_list[filename][i][j])
                            for one_line in lines:
                                
                                if res_delete_list[filename][i][j] in one_line:
                                    print(one_line)
                                    if one_line.find(' remm ')!=-1:
                                        print(one_line.split(' remm ')[0].strip())
                                        line = one_line.split(' remm ')[0].strip()
                                    elif one_line.find(' mturk ')!=-1:
                                        print(one_line.split(' mturk ')[0].strip())
                                        line = one_line.split(' mturk ')[0].strip()
                                    else:
                                        exit()
                                    
                                    backline = back_line(line, new_filename, repo_dir, CVE_ID, res_delete_list[filename][i][j])
                                    w_f.write(backline+'\t'+res_delete_list[filename][i][j]+'\n')
                                    print(backline)
                            
                            




# get cve's commit
def svn_get_CVE_commit(target_repo):
    CVE_list = get_target_cve_list(target_repo)
    #print(CVE_list)
    commit_dict = {}
    for CVE_ID in CVE_list:
        patch_info_path = dir_path + 'patch_info/'
        #patch_info_list = []
        commit_dict[CVE_ID] = []
        for parent, dirnames, filenames in os.walk(patch_info_path):
            for filename in filenames:
                if filename.find(CVE_ID)!=-1:
                    if filename.split('_')[-1].split('.')[0] not in commit_dict[CVE_ID]:
                        commit_dict[CVE_ID].append(filename.split('_')[-1].split('.')[0])
    return commit_dict

def svn_vszz(target_repo, specialCVE):
    CVE_commit_list = svn_get_CVE_commit(target_repo)
    log_file = '/vszz/vszz_output/svn_tomcat_tag2commit.json'
    with open(log_file, 'r') as f:
        commit_json = json.loads(f.read())
    #print(commit_json)
    result_list = []
    for one in CVE_commit_list:
        if one == specialCVE:
            svn_commit_id = CVE_commit_list[one]
            print(svn_commit_id)
            for commit_one in svn_commit_id:
                small_list = []
                for one_tag in commit_json:
                    if int(one_tag['revision']) <= int(commit_one):
                        #print(one_tag['tag'])
                        if one_tag['tag'] not in result_list:
                            result_list.append(one_tag['tag'])
                            small_list.append(one_tag['tag'])
                print(commit_one)
                print(small_list)

    print(specialCVE, ': ')
    result_list.sort()
    print(result_list)






specialCVE = 'CVE-2011-1475'
target_repo = 'tomcat'


svn_vszz(target_repo, specialCVE)

vszz_step1(target_repo, specialCVE)

VSZZ_path = '/vszz/vszz_output'
output_path = VSZZ_path + '/'

# gitlog_path = '/vszz/vszz_output/' + target_repo+ '/'
# read_path = VSZZ_path +'/'+ target_repo +'.txt'
#get_git_log(target_repo)
#lifetime_step3(gitlog_path,read_path, target_repo, specialCVE)


