import os
import pickle

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
