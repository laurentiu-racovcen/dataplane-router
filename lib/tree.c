#include <arpa/inet.h>
#include <string.h>
#include "lib.h"
#include "tree.h"

#define IPv4_ADDR_LENGTH 32

/* Function that initializes a binary tree */
void initTree(struct TreeNode **root) {
	(*root) = malloc(sizeof(struct TreeNode));
	(*root)->right = NULL;
	(*root)->left = NULL;
    (*root)->key = NULL;
}

/* Function that gets the length of a prefix */
uint8_t get_prefix_len(struct route_table_entry *key) {

	uint8_t prefix_len = 0;
	uint32_t key_copy = ntohl(key->mask);

	// initialize iter_bit with the first bit in mask
	uint8_t iter_bit = (key_copy << prefix_len) >> (IPv4_ADDR_LENGTH-1);

	while (iter_bit != 0) {
		prefix_len++;
		iter_bit = (key_copy << prefix_len) >> (IPv4_ADDR_LENGTH-1);
		if (prefix_len == IPv4_ADDR_LENGTH) {
			// iter_bit reached the last bit of the mask
			// to avoid cycling, iter_bit is set to 0
			iter_bit = 0;
		}
	}

	return prefix_len;

}

/* Function that inserts a prefix in the tree */
struct TreeNode* insert_prefix(struct TreeNode* root, struct route_table_entry *key) {
	if (root == NULL) {
		initTree(&root);
		return root;
	}

	// get prefix length of current prefix
	uint8_t prefix_len = get_prefix_len(key);
	// convert to host order
	uint32_t prefix_copy = ntohl(key->prefix);

	for (size_t i = 0; i < prefix_len; i++) {
		// insert nodes of the specified prefix in bits form
		uint8_t iter_bit = (prefix_copy << i) >> (IPv4_ADDR_LENGTH-1);

		if (iter_bit == 0) {
			// check if left node exists
			if (root->left != NULL) {
				// if the node exists, change the iter node
				root = root->left;
			} else {
				// if the node does NOT exist, create new left node
				root->left = calloc(1, sizeof(struct TreeNode));
				root = root->left;
			}
		} else if (iter_bit == 1) {
			// check if right node exists
			if (root->right != NULL) {
				// if the node exists, change the iter node
				root = root->right;
			} else {
				// if the node does NOT exist, create new right node
				root->right = calloc(1, sizeof(struct TreeNode));
				root = root->right;
			}
		}

		// if the last bit of the prefix is being processed,
		// set this node's key with the given key
		if (i == prefix_len - 1) {
			root->key = key;
		}
	}
	return root;
}

/* Function that returns the entry with the Longest Prefix Match (LPM) */
struct route_table_entry *get_best_route(uint32_t searched_ip, struct TreeNode* root) {
	struct route_table_entry *best_prefix_match = NULL;

	uint8_t i = 0;
	// while the root has at least one descendant, find the LPM
	while (root->left != NULL || root->right != NULL) {
		uint8_t iter_bit = (searched_ip << i) >> (IPv4_ADDR_LENGTH-1);

		// if the current node has a key from "rtable", update it
		if (root->key != NULL) {
			best_prefix_match = root->key;
		}

		// if current node has the needed descendant
		// (based on iter_bit), update current node
		if (iter_bit == 0 && root->left != NULL) {
			root = root->left;
		} else if (iter_bit == 1 && root->right != NULL) {
			root = root->right;
		}

		i++;
	}

	// in case the matching prefix is on a leaf node
	if (root->key != NULL) {
		if ((ntohl(root->key->mask) & searched_ip) == ntohl(root->key->prefix)){
			return root->key;
		}
	}
	
	return best_prefix_match;
}

/* Function that frees allocated memory of the binary tree */
void freeTree(struct TreeNode **root) {
	if ((*root) == NULL) {
		return;
	}

	freeTree(&((*root)->left));
	freeTree(&((*root)->right));
	free(*root);

	*root = NULL;
}
