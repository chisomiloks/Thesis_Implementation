import numpy as np

# charles idea
# generate policy containing at least n_attr number of attributes
def generate_policy_string(attribute_master, n_attr):
    """
    :param attribute_master: List of all attributes in the system
    :param n_attr: Number of attributes to be contained in the generated policy
    :return: A Generated policy string
    """
    policy_str = ''
    OPS = ['and', 'or']
    # attr_indices = np.random.randint(0, len(attribute_master), n_attr)
    # changes to .choice so that attributes are not repeated in the policy
    attr_indices = np.random.choice(range(len(attribute_master)), n_attr, replace=False)
    for attr_index in attr_indices:
        attribute = attribute_master[attr_index]
        # op_idx = int(np.random.randint(0, len(OPS), 1))
        # policy_str += attribute + " " + OPS[op_idx] + " "
        policy_str += attribute + " " + OPS[0] + " "

    # print('policy before: ', policy_str)
    policy_str = "(" + policy_str[:-4].strip() + ")"
    # print('policy after: ', policy_str)

    return policy_str