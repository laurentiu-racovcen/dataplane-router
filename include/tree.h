#ifndef _TREE_H_
#define _TREE_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

struct TreeNode {
    struct TreeNode *left;
    struct TreeNode *right;
    struct route_table_entry *key;
};

void initTree(struct TreeNode **root);
uint8_t get_prefix_len(struct route_table_entry *key);
struct TreeNode* insert_prefix(struct TreeNode* root, struct route_table_entry *rtable_entry);
struct route_table_entry *get_best_route(uint32_t searched_ip, struct TreeNode* root);
void freeTree(struct TreeNode **root);

#endif
