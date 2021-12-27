import argparse
import json
import os
import pickle
import sys

from fast_bpe_sim import calc_ml2p
from monte_carlo_lib import MonteCarloLib


def load_pickles(folder: str):
    def gen_path(x: str):
        return os.path.join(folder, x)

    model_pickle, inter_pickle, danger_pickle, samples_pickle = \
        gen_path('bpemodel.pickle'), gen_path('intermediate_results.pickle'), \
        gen_path('dangerous_chunks.pickle'), gen_path('monte_carlo_sample.pickle')
    with open(model_pickle, 'rb') as f_model_pickle, \
            open(inter_pickle, 'rb') as f_inter_pickle, \
            open(danger_pickle, 'rb') as f_danger_pickle, \
            open(samples_pickle, 'rb') as f_samples_pickle:
        _grammars, _terminals = pickle.load(f_model_pickle)
        _converted, _not_parsed = pickle.load(f_inter_pickle)
        _dangerous_chunks = pickle.load(f_danger_pickle)
        _samples = pickle.load(f_samples_pickle)
        return (_grammars, _terminals), (_converted, _not_parsed), _dangerous_chunks, _samples
    pass


current_dir = os.path.join(os.path.dirname(__file__), 'resources')
(grammars, terminals), (converted, not_parsed), dangerous_chunks, samples = load_pickles(current_dir)
monte_carlo = MonteCarloLib(samples)


def check_pwd(pwd: str):
    """Check the strength of given password.
    Given a password which is encoded by ascii and return strength information of the password.

    Arguments:
        pwd: The input password we need to check.
    
    Returns:
        A tuple which is consist of guess_number, segments, chunks and prob. 
        The guess_number indicates the maximal guess number of given password.
        The segments indicates the all segments.
        The chunks indicates that all dangerous chunks in the password.
        The prob is the guess probability of the password which is calculated by monte carlo method.
    """
    struct, prob = calc_ml2p(converted, not_parsed, grammars, terminals, pwd)
    chunks = []
    prev = 0
    for _, l in struct:
        sc = pwd[prev:prev + l]
        prev += l
        if sc in dangerous_chunks:
            _a = (sc, True)
        else:
            _a = (sc, False)
        chunks.append(_a)
    rank = monte_carlo.ml2p2rank(prob)
    return {
        "guess_number": rank,
        "segments": struct,
        "chunks": chunks,
        "prob": 2 ** -prob,
    }


def is_dangerous_chunk(chunk: str):
    return chunk in dangerous_chunks


def opt4xl(json_file: str):
    with open(json_file, 'r') as f_json:
        # first 5 lines are metadata and so on
        f_json.readline()
        # data_name
        f_json.readline()
        # passwd_count
        pc_line = f_json.readline()
        # passwd_count = filter(str.isdigit, f_json.readline())
        print(pc_line)

        pc = [c for c in pc_line if c.isdigit()]
        print(pc)
        passwd_count = int("".join(pc))
        yield passwd_count
        # block_list and "passwd": {
        f_json.readline()
        f_json.readline()
        j_str = ["{"]
        for line in f_json:
            line = line.strip("\r\n")
            if line.endswith('},') or line.endswith('}'):
                continue
            j_str.append(line)

            if line.endswith("]") and len(j_str) > 1:
                # parse j_str
                j_str.append("}}")
                j_str = "".join(j_str)
                print(j_str)
                info = json.loads(j_str)
                j_str = ["{"]
                pwd, = info.keys()
                v, = info.values()
                yield pwd, v['count'], v['matched_rules']
        pass
    pass


if __name__ == '__main__':
    cli = argparse.ArgumentParser("Checking Password Strength")
    # cli.add_argument("-p", '--pw', required=True, help='Passwords, one password per line')
    cli.add_argument('-r', '--rule-of-pw', required=True, help='Rules of each password')
    cli.add_argument("-s", '--save-folder', required=True,
                     help='Saving results in this folder, each line is in json format')
    args = cli.parse_args()
    save_folder = args.save_folder
    if not os.path.exists(save_folder):
        os.mkdir(save_folder)
    save_ids = [None]  # rule id starts from 1, instead of 0
    for rule_id in range(1, 8):
        save_ids.append(open(os.path.join(save_folder, f"rule-{rule_id}.txt"), 'w'))
    opted = opt4xl(args.rule_of_pw)
    total_count = next(opted)
    # with open(args.rule_of_pw) as f_pw:
    #     rule_of_pw = json.load(f_pw)
    #     all_pws = rule_of_pw['passwds']
    #     total_count = rule_of_pw['passwd_count']
    parsed_num = 0
    for _pwd, pw_cnt, pw_rules in opted:
        result = check_pwd(_pwd)
        result['pw'] = _pwd
        result['cnt'] = pw_cnt
        json_result = f"{json.dumps(result)}\n"
        for pw_rule_id in pw_rules:
            f_rule_id = save_ids[pw_rule_id]
            f_rule_id.write(json_result)
        parsed_num += 1
        if parsed_num % 10000 == 0:
            print(f"{parsed_num / total_count * 100:7.4}%", end='\r', file=sys.stderr)
        pass
    for rule_id in range(1, 8):
        save_ids[rule_id].flush()
        save_ids[rule_id].close()
    pass
