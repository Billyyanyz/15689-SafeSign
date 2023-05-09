# Implementation of a merkle tree
from math import log2, ceil, pow
from keccak256 import keccak_256_hash


def sortconcat(a, b):
    if a < b:
        return a + b
    else:
        return b + a


class merkleTreeNode:
    def __init__(self, val):
        self.left = None
        self.right = None
        self.parent = None
        self.val = val  # as bytes


class merkleTree:
    def __init__(self, leaves):

        # pad to power of 2
        padded_leaves = leaves + [bytes(0)] * int(pow(2, ceil(log2(len(leaves)))) - len(leaves))

        childrenNodes = [merkleTreeNode(keccak_256_hash(leaf)) for leaf in padded_leaves]
        self.leaves = childrenNodes

        while len(childrenNodes) != 1:
            parentNodes = []
            for i in range(0, len(childrenNodes), 2):
                leftChild = childrenNodes[i]
                rightChild = childrenNodes[i + 1]
                parent = merkleTreeNode(keccak_256_hash(sortconcat(leftChild.val, rightChild.val)))
                parent.left = leftChild
                parent.right = rightChild
                leftChild.parent = parent
                rightChild.parent = parent
                parentNodes.append(parent)
            childrenNodes = parentNodes

        self.root = childrenNodes[0]

    def check_tree_consistency(self):
        def check_tree_consistency_recursive(node):
            if node.left is None:
                return True
            valid = (keccak_256_hash(sortconcat(node.left.val, node.right.val)) == node.val)
            valid &= check_tree_consistency_recursive(node.left)
            valid &= check_tree_consistency_recursive(node.right)
            assert valid
            return valid
        return check_tree_consistency_recursive(self.root)

    def gen_auth_path(self, leaf_index):
        node = self.leaves[leaf_index]
        path = []
        while node.parent is not None:
            if node == node.parent.left:
                path.append(node.parent.right.val)
            else:
                path.append(node.parent.left.val)
            node = node.parent
        path.append(node.val)
        return path


def check_auth_path(leaf_val, auth_path):
    h = keccak_256_hash(leaf_val)
    root_hash = auth_path[-1]
    for path_hash in auth_path[:-1]:
        h = keccak_256_hash(sortconcat(h, path_hash))
    return h == root_hash


if __name__ == '__main__':
    leaves = [b'1', b'4', b'ASDDDD', b'12', b'27', b'34', b'90', b'FFG']
    tree = merkleTree(leaves)
    tree.check_tree_consistency()
    print(check_auth_path(leaves[3], tree.gen_auth_path(3)))
    print(check_auth_path(leaves[7], tree.gen_auth_path(7)))
    print(check_auth_path(leaves[1], tree.gen_auth_path(2)))
