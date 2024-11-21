import os
import subprocess
import re
import json
import sys

from collections import OrderedDict
from unidiff import PatchSet

# YOUR PATH
dir_path = ''


############# step one 
#### generate pre-patch and post-patch files 
######################
def generate_file(filename_info, repo_path, repo_name, cve_id):
    # get all commit version files .java file
    for filename, commits in filename_info.items():
        ori_commit = commits[0]
        fix_commit = commits[1]

        cmd = 'cd %s && git show %s' % (repo_path, ori_commit) #ori
        status, output = subprocess.getstatusoutput(cmd)
        #print ori_commit, status

        filename = dir_path + '/version_java_file/%s_%s_%s.java' % (repo_name, cve_id, ori_commit)
        with open(filename, 'w') as f:
            f.write(output)

        cmd = 'cd %s && git show %s' % (repo_path, fix_commit) #ori
        status, output = subprocess.getstatusoutput(cmd)
        #print fix_commit, status

        filename = dir_path + '/version_java_file/%s_%s_%s.java' % (repo_name, cve_id, fix_commit)
        with open(filename, 'w') as f:
            f.write(output)


def parse_diff(path_to_patch):
    # get diff file patch version before and after commit id
    filename_info = {}

    patches = PatchSet.from_filename(path_to_patch)
    for patch in patches:
        filename = '/'.join(patch.source_file.split('/')[1:])

        if not filename.endswith('.java'):
        	continue
        patch_info = patch.patch_info
        
        ##################################################
        #patch_info_commit: index b4394a3,1dbbc32..b47cb71
        #patch_info_commit: index 7d47c94..4de96ae 100644
        patch_info_commit = patch.patch_info[-1]
        #patch_info_processed: 7d47c94..4de96ae 100644
        patch_info_processed = patch_info_commit[6:]

        #index 7d47c94..4de96ae 100644
        ori_commit = patch_info_processed.split('..')[0]
        fix_commit = patch_info_processed.split('..')[1].split(' ')[0]

        filename_info[filename] = [ori_commit, fix_commit]
        
    #{'java/org/apache/tomcat/websocket/WsFrameBase.java': ['97c9c94b26', 'ba5813bc27']}
    #print(filename_info)

    return filename_info



def git_control_file_generate(repo_path, repo_name, cve_id):
    # for every diff file get their commit version then save java files
    
    diff_path = dir_path + '/diff_file/'
    diff_path_list = []
    for parent, dirnames, filenames in os.walk(diff_path):
        for filename in filenames:
            if filename.find(repo_name)!=-1 and filename.find(cve_id)!=-1:
                diff_path_list.append(os.path.join(parent, filename)) 

    patch_info = {}
    cnt = 0
    for diff in diff_path_list:
        if diff.find(cve_id)==-1:
            continue
        cnt = cnt+1
        print("Process %d , total %d" % (cnt, len(diff_path_list)))
        #try:
        filename_info = parse_diff(diff)
        patch_info[diff.split('/')[-1]] = filename_info
        generate_file(filename_info, repo_path, repo_name, cve_id)
        #except Exception as e:
        #    print(e)
    print()
    print('Generating commit before and after files done!') 

############### step one over


def get_added_line(func_patch):
    # for each patch, get added lines 
    target_start = func_patch.target_start
    target_length = func_patch.target_length
    target_linenum = 0
    added = []
    for target_line in func_patch.target: 
        if target_line.startswith('+'):
            if target_line.find('//')!=-1:
                continue
            added_line = target_line[1:].strip()
            if added_line == '' or added_line == '}':
                continue
            added_num = target_linenum + target_start
            added_list = OrderedDict()
            added_list["target_line_num"] = added_num
            added_list["target_line_code"] = added_line
            added.append(added_list)
        target_linenum += 1
    #print(added)
    return added


def get_removed_line(func_patch):
    # for each patch, get all removed lines
    source_start = func_patch.source_start
    source_length = func_patch.source_length
    source_linenum = 0
    removed = []
    for source_line in func_patch.source:
        if source_line.startswith('-'):
            if source_line.find('//')!=-1:
                continue
            removed_line = source_line[1:].strip()
            if removed_line == '' or removed_line == '}':
                continue
            removed_num = source_linenum + source_start
            removed_list = OrderedDict()
            removed_list["source_line_num"] = removed_num
            removed_list["source_line_code"] = removed_line
            removed.append(removed_list)
        source_linenum += 1
    #print(removed)
    return removed

def read_file_list(inputFile):
    # read file each lines
    results = []
    fin = open(inputFile, 'r')
    for eachLiine in fin.readlines():
        line = eachLiine.strip()
        results.append(line)
    fin.close()
    return results

def read_file(inputFile):
    # read file
    results = []
    try:
        fin = open(inputFile, 'r')
        result = fin.read()
        fin.close()
    except:
        with open(inputFile, 'rb') as f:   
            result = f.read().decode("GBK",errors='ignore')
    return result


def patch_func_import_handle(patch_target):
    # import and * patch handle
    normal_line = []
    for one in patch_target:
        if one.find(' *')!=-1 or one.find('/*')!=-1 or one.find('*/')!=-1:
            continue
        elif one.find('import')!=-1:
            continue
        elif one == ' \n':
            continue
        else:
            normal_line.append(one)
    return normal_line 


def patch_func_name_in_patch(patch_target):
    # patch target code have function name, use this as patch_func_name
    patch_func_name = ''
    for one_line in patch_target:
        if one_line.endswith(','):
            # public long process(SSIMediator ssiMediator, String commandName,
            #       String[] paramNames, String[] paramValues, PrintWriter writer) {
            continue
        elif one_line.strip().startswith('.'):
            # if (inputFilters[i].getEncodingName()
            #     .toString().equals(encodingName)) {
            continue
        elif one_line.endswith('&&'):
            # if (context.getIgnoreAnnotations() &&
            continue
        if re.match('.*\(.*\).*\{', one_line):
            if one_line.startswith('+'):
                one_line = one_line.split('+')[1].lstrip()
                # +// if (headerBufferSize < (8 * 1024)) {
                if one_line.startswith('//'):
                    one_line = one_line.split('//')[1].lstrip()
            else:
                one_line = one_line.lstrip()
            if one_line.startswith('if'):
                continue
            elif one_line.startswith('//'):
                continue
            elif one_line.startswith('for'):
                continue
            elif one_line.startswith('}'):
                continue
            elif one_line.startswith('switch'):
                continue
            elif one_line.startswith('while'):
                continue
            elif one_line.startswith('try'):
                continue
            elif one_line.find('} else')!=-1:
                continue
            elif one_line.strip().startswith('} else'):
                continue
            elif one_line.find('||')!=-1:
                continue
            elif one_line.find('&&')!=-1:
                continue
            elif one_line.startswith('\''):
                continue
            elif one_line.startswith('!'):
                continue
            elif one_line.find('new ')!=-1:
                # nonces = new LinkedHashMap<String, DigestAuthenticator.NonceInfo>() {
                continue
            elif one_line.find('!')!=-1:
                # !cmdLineArgumentsDecodedPattern.matcher(decodedArgument).matches()) {
                continue
            elif one_line.find('"')!=-1:
                continue
            elif one_line.startswith('#'):
                continue
            elif one_line.startswith('_'):
                continue
            elif one_line.strip().startswith('!') or \
                one_line.strip().startswith('#') or \
                one_line.strip().startswith('_') or \
                one_line.strip().startswith('@') or \
                one_line.strip().startswith('*') or \
                one_line.strip().startswith('for') or \
                one_line.strip().startswith('if') or \
                one_line.strip().startswith('and') or \
                one_line.strip().startswith('.'):
                continue
            else:
                patch_func_name = one_line
                if patch_func_name.strip() != '':
                    patch_func_name = patch_func_name.split('(')[0].strip()
                    if len(patch_func_name.split(' ')) > 1:
                        patch_func_name = patch_func_name.split(' ')[-1]
                    else:
                        patch_func_name = patch_func_name.split(' ')[0]
                if patch_func_name == 'if' or\
                    patch_func_name == 'and' or\
                    patch_func_name == 'catch' or\
                    patch_func_name == 'try' or\
                    patch_func_name == 'while' or\
                    patch_func_name == 'for':
                    patch_func_name = ''
                    continue;
                else:
                    break

    return patch_func_name


def patch_func_name_normal(cve_id, diff_file_name, filename, source_start, repo_name):
    # from one diff file find file version
    # than find that version java file
    # find the patch func name
    path_to_patch = dir_path + '/diff_file/%s' % diff_file_name
    commit_list = parse_diff(path_to_patch)
    patch_func_name = ""
    file_version = commit_list[filename]
    source_version_file = dir_path + '/version_java_file/%s_%s_%s.java' % (repo_name, cve_id, file_version[0])
    #results = read_file_list(source_version_file)
    if not os.path.isfile(source_version_file):
        print("Do not exists!", source_version_file)
        return ''
    # public static void writeOSState(PrintWriter writer, 
    #                                       int mode) {
    ori_file = read_file(source_version_file)
    ori_file = ori_file.replace(',\n', ',')
    # protected static void writeContext(PrintWriter writer, \n
    ori_file = ori_file.replace(', \n', ',')
    #     public void bind(String name, Object obj, Attributes attrs)
    #   throws NamingException {
    new_file = ori_file.replace(')\n', ')').split('\n')

    num = 1
    result = []
    for one_line in new_file:
        if num <= source_start:
            # handle two line situation
            if one_line.find(',\t'):
                # public long process(SSIMediator ssiMediator, String commandName,
                #       String[] paramNames, String[] paramValues, PrintWriter writer) {
                #line = new_file[num-1].strip() + new_file[num].strip()
                result.append(one_line)
                #source_start -= 1
            elif one_line.strip().startswith('.'):
                # if (inputFilters[i].getEncodingName()
                #     .toString().equals(encodingName)) {
                line = new_file[num-1].strip() + new_file[num].strip()
                result.append(line)
            elif one_line.endswith('&&'):
                # if (context.getIgnoreAnnotations() &&
                line = new_file[num-1].strip() + new_file[num].strip()
                result.append(line)
            else:
                result.append(one_line)
            num+=1
    result.reverse()
    for one_line in result:
        if re.match('.*\(.*\).*\{', one_line):
            if one_line.startswith('if') or \
                one_line.startswith('//') or \
                one_line.startswith('}') or \
                one_line.startswith('switch') or \
                one_line.startswith('while') or \
                one_line.startswith('try') or \
                one_line.startswith('\'') or \
                one_line.startswith('#') or \
                one_line.startswith('_') or \
                one_line.startswith('!') or \
                one_line.startswith('*') or \
                one_line.find('} else')!=-1 or \
                one_line.find('||')!=-1 or \
                one_line.find('&&')!=-1 or \
                one_line.find('new ')!=-1 or \
                one_line.find('!')!=-1 or \
                one_line.find('"')!=-1 or \
                one_line.strip().startswith('} else') or \
                one_line.startswith('for'):
                continue
            elif one_line.strip().startswith('!') or \
                one_line.strip().startswith('#') or \
                one_line.strip().startswith('_') or \
                one_line.strip().startswith('@') or \
                one_line.strip().startswith('*') or \
                one_line.strip().startswith('for') or \
                one_line.strip().startswith('if') or \
                one_line.strip().startswith('and') or \
                one_line.strip().startswith('.'):
                continue
            else:
                patch_func_name = one_line
                if patch_func_name.strip() != '':
                    patch_func_name = patch_func_name.split('(')[0].strip()
                    if len(patch_func_name.split(' ')) > 1:
                        patch_func_name = patch_func_name.split(' ')[-1]
                    else:
                        patch_func_name = patch_func_name.split(' ')[0]
                if patch_func_name == 'if' or\
                    patch_func_name == 'and' or\
                    patch_func_name == 'catch' or\
                    patch_func_name == 'try' or\
                    patch_func_name == 'while' or\
                    patch_func_name == 'for':
                    patch_func_name = ''
                    continue;
                else:
                    break

    return patch_func_name


def patch_func_name(cve_id, diff_file_name, filename, func_patch, repo_name):
    # handle import and * and /n useless patches
    normal_line = patch_func_import_handle(func_patch.target)
    if normal_line == None:
        return -1
    patch_func = ''
    # patch target code have function name
    patch_func = patch_func_name_in_patch(func_patch.target)
    # target code do not have fuc, find nearest function as patch_func
    if patch_func == '':
        patch_func = patch_func_name_normal(cve_id, diff_file_name, filename, func_patch.source_start, repo_name)
    # if this patch can not find patch function name, then drop
    if patch_func == '':
        return -1
    return patch_func




def git_control(cve_id, repo_name):
    diff_path = dir_path + '/diff_file/'
    diff_path_list = []
    for parent, dirnames, filenames in os.walk(diff_path):
        for filename in filenames:
            if filename.find(repo_name)!=-1 and filename.find(cve_id)!=-1:
                diff_path_list.append(os.path.join(parent, filename)) 

    num = 1 
    for one_diff in diff_path_list:

        diff_file_name = one_diff.split('/')[-1]
        # get diff type like: CVE-2020-11996_c8acd2ab7371e39aeca7c306f3b5380f00afe552.diff(git)
        if (diff_file_name.split('_')[1].split('.')[0]).isdigit():
            continue
        patches = PatchSet.from_filename(one_diff)
        # one file as a patch
        for patch in patches:
            filename = patch.path
            if not filename.endswith('.java'):
                continue
            patch_info = patch.patch_info
            for func_patch in patch:
                # @@ -1023,11 +1042,20 @@  public class Http2UpgradeHandler extends AbstractStream implements InternalHttpU
                # source_start,source_length,target_start,target_length,section_header
                patch_func = patch_func_name(cve_id, diff_file_name, filename, func_patch, repo_name)
                if patch_func == -1 or patch_func == None:
                    patch_func = 'no'
                added_line_list = get_added_line(func_patch)
                removed_line_list = get_removed_line(func_patch)
                if len(added_line_list)==0 and len(removed_line_list)==0:
                        continue
               
                
                func = OrderedDict()
                func["cve_id"] = one_diff.split('_')[1].split('/')[1]
                func["added_line"] = added_line_list
                func["removed_line"] = removed_line_list
                func["filename"] = filename
                func["patch_func"] = patch_func
                func["diff_file"] = diff_file_name

                patch_json = []
                patch_json.append(func)
                #print(source_tag, patch_tag)
               
                patch_filename = repo_name +'_'+ cve_id +'_'+ one_diff.split('_')[1].split('/')[1] +'_'+ \
                    filename.split('/')[-1].split('.')[0] +'_'+ patch_func + '_' + diff_file_name.split('.')[0].split('_')[-1]
                patch_info_filename = dir_path + '/patch_info/%s.json' % patch_filename

                if not os.path.isfile(patch_info_filename):
                    with open(patch_info_filename, 'w') as f:
                        f.write(json.dumps(patch_json))
                
                elif os.path.isfile(patch_info_filename):
                    # for one file one func has more than one patch
                    # do not recover
                    # add added lines and removed lines in old file
                    with open(patch_info_filename, 'r') as f:
                        oldjson = json.loads(f.read())
                    # if already in :continue
                    added_all_in = True
                    for one in patch_json[0]['added_line']:
                        if one not in oldjson[0]['added_line']:
                            added_all_in = False
                    removed_all_in = True
                    for one in patch_json[0]['removed_line']:
                        if one not in oldjson[0]['removed_line']:
                            removed_all_in = False
                    if added_all_in and removed_all_in:
                        continue
                    # have some lines needed to add in list
                    if not added_all_in and not removed_all_in:
                        new_added_lines = oldjson[0]['added_line']
                        for new_one_line in patch_json[0]['added_line']:
                            if new_one_line not in new_added_lines:
                                new_added_lines.append(new_one_line)
                        patch_json[0]['added_line'] = new_added_lines

                        new_removed_lines = oldjson[0]['removed_line']
                        for new_one_line in patch_json[0]['removed_line']:
                            if new_one_line not in new_removed_lines:
                                new_removed_lines.append(new_one_line)
                        patch_json[0]['removed_line'] = new_removed_lines

                    elif not added_all_in and removed_all_in:
                        new_added_lines = oldjson[0]['added_line']
                        for new_one_line in patch_json[0]['added_line']:
                            if new_one_line not in new_added_lines:
                                new_added_lines.append(new_one_line)
                        patch_json[0]['added_line'] = new_added_lines
                        patch_json[0]['removed_line'] = oldjson[0]['removed_line']

                    elif added_all_in and not removed_all_in:
                        new_removed_lines = oldjson[0]['removed_line']
                        for new_one_line in patch_json[0]['removed_line']:
                            if new_one_line not in new_removed_lines:
                                new_removed_lines.append(new_one_line)
                        patch_json[0]['removed_line'] = new_removed_lines
                        patch_json[0]['added_line'] = oldjson[0]['added_line'] 
                    # re save file 
                    if not added_all_in or not removed_all_in:
                        if not os.path.isfile(patch_info_filename):
                            with open(patch_info_filename, 'w') as f:
                                f.write(json.dumps(patch_json))
                            print('File changed: \n', patch_filename)
                        else:
                            os.remove(patch_info_filename)
                            with open(patch_info_filename, 'w') as f:
                                f.write(json.dumps(patch_json))
                            print('File changed: \n', patch_filename)

        print("Process %d , total %d" % (num, len(diff_path_list)))
        num += 1



repo_name = sys.argv[1]
#cve_id = 'CVE-2020-9484'
cve_id = sys.argv[2]

# repo git path
repo_path = dir_path + '/tomcat/'

# generate pre-patch and post-patch file for analysis the function name
git_control_file_generate(repo_path, repo_name, cve_id)

# analysis diff files to get patch_infos
git_control(cve_id, repo_name)