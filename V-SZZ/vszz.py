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




def new_patches_dir(tmp_patches, idx, cwe):
    _dir = 'tmp_patch_%s_%s' % (cwe, str(idx))
    if os.path.isdir(_dir) == False:
        os.mkdir(_dir)
    for patch in tmp_patches:
        shutil.copy(patch, _dir)
    return _dir

def move_vul_fix_fea(ori_dir, dest_dir, idx, cwe):
    ori_vul_file = os.path.join(ori_dir, 'vul_fingerprint_vul_fix_%s' % cwe)
    dest_vul_file = os.path.join(dest_dir, 'vul_fingerprint_vul_fix_%s_%s' % (cwe, str(idx)))
    shutil.copy(ori_vul_file, dest_vul_file)
    ori_fix_file = os.path.join(ori_dir, 'fix_pattern_features_%s' % cwe)
    dest_fix_file = os.path.join(dest_dir, 'fix_pattern_features_%s_%s' % (cwe, str(idx)))
    shutil.copy(ori_fix_file, dest_fix_file)

def combine_fea(parts, cwe, src_dir, dest_dir):
    vul_fea = {}
    fix_fea = {}
    for idx in xrange(parts):
        vul_fea_file = os.path.join(src_dir, 'vul_fingerprint_vul_fix_%s_%s' % (cwe, str(idx)))
        fix_fea_file = os.path.join(src_dir, 'fix_pattern_features_%s_%s' % (cwe, str(idx)))


        vul_fea_tmp = None
        fix_fea_tmp = None
        with open(vul_fea_file) as f:
            vul_fea_tmp = pickle.loads(f.read())
        with open(fix_fea_file) as f:
            fix_fea_tmp = pickle.loads(f.read())
        vul_fea.update(vul_fea_tmp)
        fix_fea.update(fix_fea_tmp)
    dest_vul_file = os.path.join(dest_dir, 'vul_fingerprint_vul_fix_%s' % cwe)
    dest_fix_file = os.path.join(dest_dir, 'fix_pattern_features_%s' % cwe)
    with open(dest_vul_file, 'w') as f:
        f.write(pickle.dumps(vul_fea))
    with open(dest_fix_file, 'w') as f:
        f.write(pickle.dumps(fix_fea))

#process content, and record the line num of the each function 
def get_unit_start_pos_list(content, filename):
    pos_list = []
    for i in xrange(len(content)):
        if content[i].strip() == filename:
            pos_list.append(i)
    pos_list.append(len(content)+3)
    return pos_list

def get_hash(string):
    if string == None:
        return ''
    #print string

    #remove tab, space, empty line
    line_stmts = string.split('\n')
    #print line_stmts    
    #print 

    replaced = re.sub('[ \t\n]', '', string)
    #print replaced

    return hashlib.sha256(replaced).hexdigest()

def get_func_pos_mapping_content(filename_func,filename):
    func_pos = {} #function_name: [start, pos, content_hash]
    content = linecache.getlines(filename_func)
    start_list = get_unit_start_pos_list(content, filename)
    #print 'start_list', start_list


    for idx in xrange(len(start_list)-1):
        start = start_list[idx]
        end = start_list[idx+1]

        pos_line = content[start+3].strip()
        arr_tmp = pos_line.split('\t')
        function_name = content[start+2].strip()
        function_name = function_name.replace(' ', '')
        #print 'postion info:', arr_tmp
        #print 'function_name', function_name

        function_content = ''.join(content[start+9:end-3])
        #print function_content
        function_content_processed = pre_process_remove_comments(function_content)
        #print 'processed', function_content_processed
        #print
        content_hash = get_hash(function_content_processed)
        func_pos[function_name] = [int(arr_tmp[0]), int(arr_tmp[1]), content_hash]
    #print 'func_pos', func_pos
    linecache.clearcache()
    return func_pos

def __get_func_pos_mapping(commit_id, repo_path):
    cmd = 'cd %s && git show %s' % (repo_path, commit_id)
    status,output = subprocess.getstatusoutput(cmd)
    filename = 'diff_file_dir_one/%s.c' % (commit_id)
    with open(filename, 'w') as f:
        output = output.replace(' _U_', '')
        f.write(output)

    #print 'FuncParser ... ', filename
    cmd_parse = 'java -Xmx1024m -jar FuncParser-opt.jar %s'  % (filename)
    status, output = subprocess.getstatusoutput(cmd_parse)
    #print 'get_func_pos_mapping', output
    filename_func = 'tmp_%s_%s_%s' % \
        (commit_id,str(time.time()),str(random.random())[-6:])
    with open(filename_func, 'w') as f:
        f.write(output)
    #print 'FuncParser Done !'
    #print status, output
    func_pos = None
    try:
        #print 'get_func_pos_mapping_content ...'
        func_pos = get_func_pos_mapping_content(filename_func,filename)
        #print func_pos
    except Exception as e:
        with open('__get_func_pos_mapping_error', 'a+') as f:
            f.write('commit_id: %s, repo:%s' % (commit_id, repo_path.split('/')[-1]))
    finally:
        os.remove(filename_func)
        #os.remove(filename)
    return func_pos


def get_func_pos_mapping(ori_commit, fix_commit, repo_path):
    func_pos_ori = __get_func_pos_mapping(ori_commit, repo_path)
    func_pos_fix = __get_func_pos_mapping(fix_commit, repo_path)

    return func_pos_ori, func_pos_fix


def parse_diff(path_to_patch, repo_path):
    #[[filename, unpatched diff commit, patched diff commit], [...]]
    filename2diff = []
    #[
    # [filename, func1, func2],
    # {func1:[[added stmts],[added lines list],[deleted stmts],[deleted lines list]], 
    #  func2:[[],[],[],[]]},
    # [],
    # {}
    #]
    diff_info_list = []
    from unidiff import PatchSet
    patches = PatchSet.from_filename(path_to_patch)
    res_add_index = {}
    res_add_list = {}
    res_delete_list = {}
    res_delete_index = {}
    for patch in patches:
        print ('filename_path',patch.source_file)
        print ('filename_path_v2', '/'.join(patch.source_file.split('/')[1:]))
        filename = patch.source_file.split('/')[-1].strip()
        print ('path_to_patch', path_to_patch)
        repo = path_to_patch.split('/')[-1].split('_')[0]
        filename = '/'.join(patch.source_file.split('/')[1:])

        fname = filename
        res_add_index[fname] = []
        res_delete_index[fname] = []
        res_add_list[fname] = []
        res_delete_list[fname] = []
        
        if filename.find('.c') == -1:
            continue

        diff_info = [filename]

        patch_info = patch.patch_info
        #print '\npatch_info'
        #print patch_info

        ##################################################
        #patch_info_commit: index b4394a3,1dbbc32..b47cb71
        #patch_info_commit: index 7d47c94..4de96ae 100644
        patch_info_commit = patch.patch_info[-1]
        #patch_info_processed: 7d47c94..4de96ae 100644
        patch_info_processed = patch_info_commit[6:]
        #index 7d47c94..4de96ae 100644
        ori_commit = patch_info_processed.split('..')[0]
        fix_commit = patch_info_processed.split('..')[1].split(' ')[0]

        '''
        #index b4394a3,1dbbc32..b47cb71
        if ori_commit.find(',') != -1:
            tmp_str = ori_commit
            ori_commit = tmp_str.split(',')[0]
            fix_commit = tmp_str.split(',')[1]
        '''

        #print 'ori_commit', ori_commit
        #print 'fix_commit', fix_commit
        filename2diff.append([filename, ori_commit, fix_commit])

        #print 'get_func_pos_mapping ... '
        #parse ori and fix file to get mapping between function and postion
        #function:[start_pos, end_pos]
        function_pos_mapping_ori,  function_pos_mapping_fix  = \
            get_func_pos_mapping(ori_commit, fix_commit, repo_path) #os.path.join(repo_path, repo))

        #print 'function_pos_mapping_ori', function_pos_mapping_ori
        #print 'function_pos_mapping_fix', function_pos_mapping_fix

        func_changed_dict = {}
        #function_name: [added_line_list, deleted_line_list, added_line_idx_list, deleted_line_idx_list]
        #@@ -147,6 +147,7 @@ cvt_by_tile( TIFF *in, TIFF *out )
        for hunk in patch:
            #print hunk
            added_line_list = []
            deleted_line_list = []
            added_line_index_list = []
            deleted_line_index_list = []

            src_length = hunk.source_length  #6
            src_start = int(hunk.source_start)  #147 
            target_length = hunk.target_length #7
            target_start = int(hunk.target_start) #147
            section_header = hunk.section_header #cvt_by_tile( TIFF *in, TIFF *out )

            #print 
            #print src_start, target_start

            source_line_list = hunk.source
            target_line_list = hunk.target

            #记录删除的行，所有的空格删除，为了把重复出现在删除和增加的行的语句从增加的语句中删除
            tmp_for_deleted_list = []

            for index in xrange(len(source_line_list)):
                src_line = (source_line_list[index]).strip()
                if src_line.find('-') == 0:
                    deleted_line = src_line[1:].strip()
                    #if line ends with {, then remove {
                    if len(deleted_line) > 0 and deleted_line[-1] == '{':
                        deleted_line = deleted_line[:-1]
                    if len(deleted_line) == 0 or deleted_line == '}':
                        continue
                    deleted_line_list.append(deleted_line)
                    deleted_line_index_list.append(src_start+index)
                    tmp_for_deleted_list.append(deleted_line.replace(' ', ''))
            res_delete_list[fname].append(deleted_line_list)
            res_delete_index[fname].append(deleted_line_index_list)

            for index in xrange(len(target_line_list)):
                target_line = target_line_list[index].strip()
                if target_line.find('+') == 0:
                    #print target_line
                    added_line = target_line[1:].strip()
                    if len(added_line) > 0 and added_line[-1] == '{':
                        added_line = added_line[:-1]
                    if len(added_line) == 0 or added_line == '}':
                        continue
                    tmp_added_line = added_line.replace(' ', '')
                    #if tmp_added_line in tmp_for_deleted_list:
                    #    continue
                    added_line_list.append(added_line)
                    added_line_index_list.append(target_start+index)
            res_add_list[fname].append(added_line_list)
            res_add_index[fname].append(added_line_index_list)

            ''' 
            print 'deleted_line_index_list', deleted_line_index_list
            print 'added_line_index_list', added_line_index_list
            print 'deleted_line_list', deleted_line_list
            print 'added_line_list', added_line_list
            print deleted_line_index_list == added_line_index_list
            print deleted_line_list == added_line_list
            '''

    #         for index_ in xrange(len(deleted_line_index_list)):
    #             for func, pos in function_pos_mapping_ori.items():
    #                 idx = deleted_line_index_list[index_]
    #                 if idx >= pos[0] and idx <= pos[1]:
    #                     diff_info.append(func)
    #                     if func_changed_dict.has_key(func) == False:
    #                         func_changed_dict[func] = [[],\
    #                              [deleted_line_list[index_]],[], \
    #                              [deleted_line_index_list[index_]]]
    #                     else:
    #                         func_changed_dict[func][1].append(deleted_line_list[index_])
    #                         func_changed_dict[func][3].append(deleted_line_index_list[index_])

    #         for index_ in xrange(len(added_line_index_list)):
    #             for func, pos in function_pos_mapping_fix.items():
    #                 idx = added_line_index_list[index_]
    #                 if idx >= pos[0] and idx <= pos[1]:
    #                     diff_info.append(func)
    #                     if func_changed_dict.has_key(func) == False:
    #                         func_changed_dict[func] = [\
    #                              [added_line_list[index_]],[],\
    #                              [added_line_index_list[index_]], []]
    #                     else:
    #                         func_changed_dict[func][0].append(added_line_list[index_])
    #                         func_changed_dict[func][2].append(added_line_index_list[index_])


    #     diff_info_list.append(diff_info)
    #     diff_info_list.append(func_changed_dict)

    # filename2diff_new = []
    # diff_info_list_new = []
    # for idx in xrange(len(filename2diff)):
    #     function_info = diff_info_list[2*idx+1]
    #     if len(function_info.items()) == 0:
    #         continue
    #     filename2diff_new.append(filename2diff[idx])
    #     diff_info_list_new.append([diff_info_list[2*idx][0]] + \
    #             list(set(diff_info_list[2*idx][1:])))
    #     diff_info_list_new.append(diff_info_list[2*idx+1])
    # print filename2diff_new, diff_info_list_new
    # return filename2diff_new, diff_info_list_new

    return res_delete_index,res_delete_list,res_add_index,res_add_list





def get_parent_commit():
    read_file = '/vul_pat_feature/parent_commit.txt'
    f=open(read_file,'r')
    line = f.readline()
    commit_dict = {}
    while line:
        if 'CVE' in line:
            cve_num=line.replace('\n','')
            fix_commit = cve_num.split('_')[-1]
            line = f.readline()
            par_commit=line.replace('\n','').split('/')[-1]
            commit_dict[cve_num]=[fix_commit,par_commit]
            #print(commit_dict)
            #print(fix_commit)
        line = f.readline()
    return commit_dict

def num_fenge(n):
    num = 0
    for strs in n:
        if strs == '.':
            num+=1
    return num

def sort_new(list1):
    n = len(list1)
    while n>1:
        j=0
        while j<n-1:
            temp1 = list1[j].split('.')[0]
            temp2 = list1[j+1].split('.')[0]

            if int(temp1)>int(temp2):
                list1[j],list1[j+1] = list1[j+1],list1[j]
            elif int(temp1) == int(temp2):
                temp1 = list1[j].split('.')[1]
                temp2 = list1[j+1].split('.')[1]
                if int(temp1)>int(temp2):
                    list1[j],list1[j+1] = list1[j+1],list1[j]
                elif int(temp1) == int(temp2):
                    if num_fenge(list1[j]) == 1:
                        temp1 = 0
                    else:
                        temp1 = list1[j].split('.')[2]
                    if num_fenge(list1[j+1]) == 1:
                        temp2 = 0
                    else:
                        temp2 = list1[j+1].split('.')[2]
                    if int(temp1)>int(temp2):
                        list1[j],list1[j+1] = list1[j+1],list1[j]
           
            j+=1
        n-=1


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

def get_parcommit(fix_commit):
    command = 'cd vul_detect_src/src_repo/FFmpeg && git checkout '+fix_commit
    print(command)
    os.system(command)
    command = 'cdvul_detect_src/src_repo/FFmpeg && git log > vul_detect_src/mvp/vul_pat_feature/vszz_output/tmp_data2'
    print(command)
    os.system(command)
    rf = open('/vul_detect_src/mvp/vul_pat_feature/vszz_output/tmp_data2', 'r')
    line1 = rf.readline()
    if line1.startswith('commit') and fix_commit in line1:
        line1=rf.readline()
        while line1:
            if line1.startswith('commit'):
                par_commit = line1.split(' ')[-1].replace('\n','')
                break
            line1=rf.readline()
        line1 = rf.readline()
    # command = 'cd /vul_detect_src/src_repo/FFmpeg && git checkout master'
    # os.system(command)
    return par_commit

def get_str(line):
    flag= re.search((r'[0-9]{4}\-[0-9]{2}\-[0-9]{2}\ [0-9]{2}\:[0-9]{2}\:[0-9]{2}.*'),line).group().find(')')
    string = re.search((r'[0-9]{4}\-[0-9]{2}\-[0-9]{2}\ [0-9]{2}\:[0-9]{2}\:[0-9]{2}.*'),line).group()[flag+1:]
    return string

def get_line_num(line):
    string = re.search((r'[0-9]{4}\-[0-9]{2}\-[0-9]{2}\ [0-9]{2}\:[0-9]{2}\:[0-9]{2}.*'),line).group().split(')')[0].split(' ')[-1]
    return string

def get_filename(line):
    string = line.split(' ')[1]
    return string

def get_back_line_num(commit,string,filename):
    if '6ef14e5753e' in commit:
        return None
    command = 'cd /vul_detect_src/src_repo/FFmpeg && git show '+ commit+' > /vul_detect_src/mvp/vul_pat_feature/vszz_output/tmp_data3'
    print(command)
    os.system(command)
    res_delete,res_delete_list,res_add_index,res_add_list=parse_diff('/vul_detect_src/mvp/vul_pat_feature/vszz_output/tmp_data3', '~/vul_detect_src/src_repo/FFmpeg/')
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
    


def back_line(line,filename):
    commit = line.split(' ')[0]
    str1 = get_str(line)
    par_commit = get_parcommit(commit)
    filename_new = get_filename(line)
    if filename_new.endswith('.c'):
        filename=filename_new
    print(filename)
    line_num = get_back_line_num(commit,str1,filename)
    if line_num == None:
        return line
    print(line_num)
    command = 'cd /vul_detect_src/src_repo/FFmpeg && git checkout '+par_commit
    os.system(command)
    command = 'cd /vul_detect_src/src_repo/FFmpeg && git blame' + ' -L '+str(line_num)+','+str(line_num)+' '+filename+' > /vul_detect_src/mvp/vul_pat_feature/vszz_output/tmp_data'
    print(command)
    os.system(command)
    rf = open('/vul_detect_src/mvp/vul_pat_feature/vszz_output/tmp_data', 'r')
    line1 = rf.readline()
    if len(line1) == 0:
        return line
    line1 = line1.replace('\n', '')
    str2 = get_str(line1)
    
    print(Levenshtein_Distance(str1, str2))
    if Levenshtein_Distance(str1, str2) < 0.75:
        return line
    else:
        return back_line(line1,filename)


def vszz_step1():
    repo_dir = '~/vul_detect_src/src_repo/FFmpeg/'   #项目所在目录
    parent_commit_dict = get_parent_commit()
    output_file = 'vszz_output/'   #输出目录
    for key in parent_commit_dict.keys():
        # if 'FFmpeg_CVE-2018-1999010_CWE-125_cced03dd667a5df6df8fd40d8de0bff477ee02e8' not in key:
        #     continue
        patch_path = '/vul_detect_src/GT_for_vul_range/patch/FFmpeg/' + key#FFmpeg_CVE-2015-8216_CWE-17_d24888ef19ba38b787b11d1ee091a3d94920c76a'   #补丁所在目录
        
        res_delete, res_delete_list, res_add_index, res_add_list = parse_diff(patch_path,repo_dir)
        add_n = 0
        add_d = 0
        for filename in res_add_index:
            for i in res_add_index[filename]:
                add_n+=len(i)
            for j in res_delete[filename]:
                add_d+=len(j)
        if (add_n+add_d)>5 or add_d == 0:
            continue
        w_f = open(output_file+key,'w')
        for filename in res_delete:
            for i in range(len(res_delete[filename])):
                if len(res_delete[filename][i]):
                    for j in range(len(res_delete_list[filename][i])):
                        command = 'cd /vul_detect_src/src_repo/FFmpeg && git checkout ' + parent_commit_dict[key][1]
                        print(command)  
                        os.system(command) #checkout到blame版本
                        command = 'cd /vul_detect_src/src_repo/FFmpeg && git blame' + ' -L '+str(res_delete[filename][i][j])+','+str(res_delete[filename][i][j])+' '+filename+' > /vul_detect_src/mvp/vul_pat_feature/vszz_output/tmp_data'
                        print(command)
                        os.system(command)
                        rf = open('/vul_detect_src/mvp/vul_pat_feature/vszz_output/tmp_data', 'r')
                        line = rf.readline().replace('\n', '')
                        print(line)
                        backline=back_line(line,filename)
                        w_f.write(backline+'\n')
                        print(backline)
                        
                        # print(res_delete_list[filename][i][j])
                        # print(res_delete[filename][i][j])
        
            
        command = 'cd /vul_detect_src/src_repo/FFmpeg && git checkout master'
        #print(res_delete,res_delete_list)
        print(command)
        # exit(0)
        #os.system(command)
        #

def lifetime_step2(rootdir,path):
    #rootdir是待分析的数据（去重），path是待写入的数据
    #rootdir = '/vul_detect_src/mvp/vul_pat_feature/vul_lifetime_output_bak'
    #path = '/vul_detect_src/mvp/vul_pat_feature/vul_lifetime_output/'
    w_path='/vul_detect_src/mvp/vul_pat_feature/vszz_output/res_1.txt'
    write_file=open(w_path,'w')
    list=os.listdir(rootdir)
    for i in list:
        if 'FFmpeg' not in i:
            continue
        print(i)
        # if 'FFmpeg_CVE-2014-9317_CWE-119_79ceaf827be0b070675d4cd0a55c3386542defd8' not in i:
        #     continue
        dict_fre={}
        dict_time = {}
        i1=path+i
        file = open(i1,'r')
        line = file.readline()
        while line:
            key = line.split(' ')[0]
            line1 = line
            temp = re.search((r'[0-9]{4}\-[0-9]{2}\-[0-9]{2}\ [0-9]{2}\:[0-9]{2}\:[0-9]{2}'),line1).group()
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
        res_dict[temp_fre] = dict_time[temp_fre]
        
        temp_key = i.split('.log')[0]
        res_dict1=sorted(res_dict.items(), key = lambda kv:(kv[1], kv[0]))
        write_file.write(temp_key+'\n'+res_dict1[0][0]+' '+res_dict1[0][1]+'\n')
        print(res_dict)
        print(dict_fre)


def in_version(string,gitlog_path):
    list=os.listdir(gitlog_path)
    result = []
    for i in list:
        if 'rc' not in i:
            i1=gitlog_path+'/'+i
            f=open(i1,'r')
            line=f.readline()
            while line:
                if string in line:
                    result.append(i)
                    break
                line = f.readline()
    return result

def ifcherry(cve_num):#cve_num:FFmpeg_CVE-2018-13301_CWE-476_2aa9047486dbff12d9e040f917e5f799ed2fd78b
    fixcommit=cve_num.split('_')[-1]
    flag=0
    command = 'cd /vul_detect_src/src_repo/FFmpeg && git show '+fixcommit+' > /vul_detect_src/mvp/vul_pat_feature/vszz_output/temp_git_show.txt'
    print(command)
    os.system(command)
    from unidiff import PatchSet
    patches = PatchSet.from_filename('/vul_detect_src/mvp/vul_pat_feature/vszz_output/temp_git_show.txt')
    
    patch_info = patches[0].patch_info
    
    return patch_info

def lifetime_step3(gitlog_path,read_path):
    
    r_f = open(read_path,'r')
    line = r_f.readline()

    w_f=open('vszz_output/res_2.txt','w')
    while line:
        if 'CVE' in line:
            # if 'f4fb841ad13bab66d4fb0c7ff2a94770df7815d8' not in line:
            #     continue
            list2_key=line.replace('\n','').split('_')[-1]
            print(list2_key)
            w_f.write(line)
            line=r_f.readline()
            list1_key=line.split(' ')[0]
            list1 = in_version(list1_key,gitlog_path)
            print(list1)
            list2=in_version(list2_key,gitlog_path)
            print(list2)
            flag=0
            patch_info = ifcherry(list2_key)
            for line in patch_info:
                if 'cherry picked' in line:
                    flag = 1
                    pickcommit = line.split('cherry picked from commit ')[-1].replace(')\n','')
                    pickcommit=str(pickcommit)
            if flag == 1:
                list2_key=pickcommit
            list2_temp=in_version(list2_key,gitlog_path)
            list2_1=list2
            list2=[i for i in list2_temp if i not in list2_1]
            for i in list2_1:
                list2.append(i)
            print(list2)
            list1_not_in_list2 = [i for i in list1 if i not in list2]
            print(list1_not_in_list2)
            w_f.write(str(list1_not_in_list2)+'\n')
        line=r_f.readline()

if __name__ == '__main__':
    #repo_dir = '~/vul_detect_src/src_repo/FFmpeg/'
    #patch_path = '/vul_detect_src/GT_for_vul_range/patch/FFmpeg/'+key 

    #需要新建一个vszz_output 目录
    #step2、step3是实现通过commit找到影响版本的功能，java好像管理方式不一样，所以2、3函数应该用不到
    #step1就是实现寻找vcc，具体路径在函数中，我注释了相关信息
    vszz_step1()  

    # rootdir = '/vul_detect_src/mvp/vul_pat_feature/vszz_output'
    # path = '/vul_detect_src/mvp/vul_pat_feature/vszz_output/'
    # lifetime_step2(rootdir,path)

    # gitlog_path = 'FFmpeg_commit_list'
    # read_path = 'vszz_output/res_1.txt'
    # lifetime_step3(gitlog_path,read_path)
    
    
