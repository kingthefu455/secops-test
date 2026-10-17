import time


def output_handler(func):
    return func


def unix_now():
    return int(time.time() * 1000)


def flat_dict_to_csv(flat_dict):
    return ["Key,Value"] + ["{},{}".format(k, v) for k, v in flat_dict.items()]
