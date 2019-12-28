/*
 * ac.c
 *
 * Implementation of the Aho-Corasick algorithm.
 *
 * NOTES:
 *    8/94  -  Original Implementation  (Sean Davis)
 *    9/94  -  Redid Implementation  (James Knight)
 *    3/96  -  Modularized the code  (James Knight)
 *    7/96  -  Finished the modularization  (James Knight)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ac.h"



/*
 * ac_alloc
 *
 * Creates a new AC_STRUCT structure and initializes its fields.
 *
 * Parameters:    none.
 *
 * Returns:  A dynamically allocated AC_STRUCT structure.
 */
AC_STRUCT *ac_alloc(void)
{
  AC_STRUCT *node;

  if ((node = malloc(sizeof(AC_STRUCT))) == NULL)
    return NULL;
  memset(node, 0, sizeof(AC_STRUCT));

  if ((node->tree = malloc(sizeof(ACTREE_NODE))) == NULL) {
    free(node);
    return NULL;
  }
  memset(node->tree, 0, sizeof(ACTREE_NODE));

  return node;
}


/*
 * ac_add_string
 *
 * Adds a string to the AC_STRUCT structure's keyword tree.
 *
 * NOTE:  The `id' value given must be unique to any of the strings
 *        added to the tree, and must be a small integer greater than
 *        0 (since it is used to index an array holding information
 *        about each of the strings).
 *
 *        The best id's to use are to number the strings from 1 to K.
 *
 * Parameters:   node      -  an AC_STRUCT structure
 *               P         -  the sequence
 *               M         -  the sequence length
 *               id        -  the sequence identifier
 *
 * Returns:  non-zero on success, zero on error.
 */
int ac_add_string(AC_STRUCT *node, char *P, int M, int id)
{
  int i, j, newsize;
  AC_TREE tnode, child, back, newnode, list, tail;

  /*
   * Return a zero if a previous error had occurred, or if the
   * given id equals zero.  An id value of zero is used by the 
   * algorithm to signal that no pattern ends at a node in the
   * keyword tree.  So, it can't be used as a pattern's id.
   */
  if (node->errorflag || id == 0)
    return 0;

  P--;            /* Shift to make sequence be P[1],...,P[M] */

  /*
   * Allocate space for the new string's information.
   */
  if (node->Psize <= id) {
    if (node->Psize == 0) {
      newsize = (id >= 16 ? id + 1 : 16);
      node->Plengths = malloc(newsize * sizeof(int));
    }
    else {
      newsize = node->Psize + id + 1;
      node->Plengths = realloc(node->Plengths, newsize * sizeof(int));
    }
    if (node->Plengths == NULL) {
      node->errorflag = 1;
      return 0;
    }

    for (i=node->Psize; i < newsize; i++)
      node->Plengths[i] = 0;
    node->Psize = newsize;
  }

  if (node->Plengths[id] != 0) {
    fprintf(stderr, "Error in Aho-Corasick preprocessing.  "
            "Duplicate identifiers\n");
    return 0;
  }

  /*
   * Add the string to the keyword tree.
   */
  tnode = node->tree;
  for (i=1; i <= M; i++) {
    /*
     * Find the child whose character is P[i].
     */
    back = NULL;
    child = tnode->children;
    while (child != NULL && child->ch < P[i]) {
      back = child;
      child = child->sibling;
    }

    if (child == NULL || child->ch != P[i])
      break;

    tnode = child;

#ifdef STATS
    node->prep_old_edges++;
#endif
  }

  /*
   * If only part of the pattern exists in the tree, add the
   * rest of the pattern to the tree.
   */
  if (i <= M) {
    list = tail = NULL;
    for (j=i; j <= M; j++) {
      if ((newnode = malloc(sizeof(ACTREE_NODE))) == NULL)
        break;
      memset(newnode, 0, sizeof(ACTREE_NODE));
      newnode->ch = P[j];

      if (list == NULL)
        list = tail = newnode;
      else
        tail = tail->children = newnode;

#ifdef STATS
      node->prep_new_edges++;
#endif
    }
    if (j <= M) {
      while (list != NULL) {
        tail = list->children;
        free(list);
        list = tail;
      }
      return 0;
    }

    list->sibling = child;
    if (back == NULL)
      tnode->children = list;
    else
      back->sibling = list;

    tnode = tail;
  }

  tnode->matchid = id;
  node->Plengths[id] = M;
  node->ispreprocessed = 0;

  return 1;
}


/*
 * ac_del_string
 *
 * Deletes a string from the keyword tree.
 *
 * Parameters:   node  -  an AC_STRUCT structure
 *               P     -  the sequence to be deleted
 *               M     -  its length
 *               id    -  its identifier
 *
 * Returns:  non-zero on success, zero on error.
 */
int ac_del_string(AC_STRUCT *node, char *P, int M, int id)
{
  int i, flag;
  AC_TREE tnode, tlast, tback, child, back;

  if (node->errorflag || id > node->Psize || node->Plengths[id] == 0)
    return 0;

  P--;            /* Shift to make sequence be P[1],...,P[M] */

  /*
   * Scan the tree for the path corresponding to the keyword to be deleted.
   */
  flag = 1;
  tlast = tnode = node->tree;
  tback = NULL;

  for (i=1; i <= M; i++) {
    /*
     * Find the child matching P[i].  It must be there.
     */
    child = tnode->children;
    back = NULL;
    while (child != NULL && child->ch != P[i]) {
      back = child;
      child = child->sibling;
    }

    if (child == NULL) {
      fprintf(stderr, "Error in Aho-Corasick preprocessing.  String to be "
              "deleted is not in tree.\n");
      return 0;
    }

    /*
     * Try to find the point where the pattern to be deleted branches off
     * from the paths of the other patterns in the tree.  This point must
     * be at the latest node which satisfies one of these two conditions:
     *
     *    1) Another pattern ends at that node (and so
     *       `child->matchid != 0').  In this case, the branch point is
     *       just below this node and so the children of this node
     *       should be removed.
     *    2) A node has other siblings.  In this case, the node itself
     *       is the branch point, and it and its children should be
     *       removed.
     */
    if (i < M && child->matchid != 0) {
      flag = 1;
      tlast = child;
    }
    else if (back != NULL || child->sibling != NULL) {
      flag = 2;
      tlast = child;
      tback = (back == NULL ? tnode : back);
    }

    tnode = child;
  }

  /*
   * If the node corresponding to the end of the keyword has children,
   * then the tree should not be altered, except to remove the keyword's
   * identifier from the tree.
   *
   * Otherwise, apply the appropriate removal, as described above.
   */
  if (tnode->children != NULL) {
    tnode->matchid = 0;
  }
  else {
    if (flag == 1) {
      child = tlast->children;
      tlast->children = NULL;
      tlast = child;
    }
    else {
      if (tback->children == tlast)
        tback->children = tlast->sibling;
      else
        tback->sibling = tlast->sibling;
    }

    while (tlast != NULL) {
      child = tlast->children;
      free(tlast);
      tlast = child;
    }
  }

  node->Plengths[id] = 0;
  node->ispreprocessed = 0;

  return 1;
}


/*
 * ac_prep
 *
 * Compute the failure and output links for the keyword tree.
 *
 * Parameters:  node  -  an AC_STRUCT structure
 *
 * Returns: non-zero on success, zero on error.
 */
int ac_prep(AC_STRUCT *node)
{
  char x;
  AC_TREE v, vprime, w, wprime, root, front, back, child;

  if (node->errorflag)
    return 0;

  /*
   * The failure link and output link computation requires a breadth-first
   * traversal of the keyword tree.  And, to do that, we need a queue of
   * the nodes yet to be processed.
   *
   * The `faillink' fields will be used as the pointers for the queue
   * of nodes to be computed (since the failure link is only set after
   * the node is removed from the queue).
   * 
   * The `outlink' fields will be used as the pointers to a node's parent
   * for nodes in the queue (since the output link is also only set after
   * the node is removed from the queue).
   */
  root = node->tree;

  front = back = root;
  front->faillink = NULL;
  front->outlink = NULL;

  while (front != NULL) {
    v = front;
    x = v->ch;
    vprime = v->outlink;

    /*
     * Add the node's children to the queue.
     */
    for (child=v->children; child != NULL; child=child->sibling) {
      child->outlink = v;
      back->faillink = child;
      back = child;
    }
    back->faillink = NULL;

    front = front->faillink;
    v->faillink = v->outlink = NULL;
    
    /*
     * Set the failure and output links.
     */
    if (v == root)
      ;
    else if (vprime == root)
      v->faillink = root;
    else {
      /*
       * Find the find link in the failure link chain which has a child
       * labeled with x.
       */
      wprime = NULL;
      w = vprime->faillink;

      while (1) {
        wprime = w->children;
        while (wprime != NULL && wprime->ch < x)
          wprime = wprime->sibling;

        if ((wprime != NULL && wprime->ch == x) || w == root)
          break;

        w = w->faillink;

#ifdef STATS
        node->prep_fail_compares++;
#endif
      }
#ifdef STATS
      node->prep_fail_compares++;
#endif

      if (wprime != NULL && wprime->ch == x)
        v->faillink = wprime;
      else
        v->faillink = root;

      if (v->matchid != 0) {
        if (v->faillink->matchid != 0)
          v->outlink = v->faillink;
        else
          v->outlink = v->faillink->outlink;
      }
    }
  }

  node->ispreprocessed = 1;
  node->initflag = 0;

  return 1;
}


/*
 * ac_search_init
 *
 * Initializes the variables used during an Aho-Corasick search.
 * See ac_search for an example of how it should be used.
 *
 * Parameters:  node  -  an AC_STRUCT structure
 *              T     -  the sequence to be searched
 *              N     -  the length of the sequence
 *
 * Returns:  nothing.
 */
void ac_search_init(AC_STRUCT *node, char *T, int N)
{
  if (node->errorflag)
    return;
  else if (!node->ispreprocessed) {
    fprintf(stderr, "Error in Aho-Corasick search.  The preprocessing "
            "has not been completed.\n");
    return;
  }

  node->T = T - 1;          /* Shift to make sequence be T[1],...,T[N] */
  node->N = N;
  node->c = 1;
  node->w = node->tree;
  node->output = NULL;
  node->initflag = 1;
  node->endflag = 0;
}


/*
 * ac_search
 *
 * Scans a text to look for the next occurrence of one of the patterns
 * in the text.  An example of how this search should be used is the
 * following:
 *
 *    s = T;
 *    len = N; 
 *    contflag = 0;
 *    ac_search_init(node, T, N);
 *    while ((s = ac_search(node, &matchlen, &matchid) != NULL) {
 *      >>> Pattern `matchid' matched from `s' to `s + matchlen - 1'. <<<
 *    }
 *
 * where `node', `T' and `N' are assumed to be initialized appropriately.
 *
 * Parameters:  node           -  a preprocessed AC_STRUCT structure
 *              length_out     -  where to store the new match's length
 *              id_out         -  where to store the identifier of the
 *                                pattern that matched
 *
 * Returns:  the left end of the text that matches a pattern, or NULL
 *           if no match occurs.  (It also stores values in `*length_out',
 *           and `*id_out' giving the match's length and pattern identifier.
 */
char *ac_search(AC_STRUCT *node, int *length_out, int *id_out)
{
  int c, N, id;
  char *T;
  AC_TREE w, wprime, root;

  if (node->errorflag)
    return NULL;
  else if (!node->ispreprocessed) {
    fprintf(stderr, "Error in Aho-Corasick search.  The preprocessing "
            "has not been completed.\n");
    return NULL;
  }
  else if (!node->initflag) {
    fprintf(stderr, "Error in Aho-Corasick search.  ac_search_init was not "
            "called.\n");
    return NULL;
  }
  else if (node->endflag)
    return NULL;

  T = node->T;
  N = node->N;
  c = node->c;
  w = node->w;
  root = node->tree;

  /*
   * If the last call to ac_search returned a match, check for another
   * match ending at the same right endpoint (denoted by a non-NULL
   * output link).
   */
  if (node->output != NULL) {
    node->output = node->output->outlink;
#ifdef STATS
    node->outlinks_traversed++;
#endif

    if (node->output != NULL) {
      id = node->output->matchid;
      if (id_out)
        *id_out = id;
      if (length_out)
        *length_out = node->Plengths[id];

      return &T[c] - node->Plengths[id];
    }
  }

  /*
   * Run the search algorithm, stopping at the first position where a
   * match to one of the patterns occurs.
   */
  while (c <= N) {
    /*
     * Try to match the next input character to a child in the tree.
     */
    wprime = w->children;
    while (wprime != NULL && wprime->ch != T[c])
      wprime = wprime->sibling;

#ifdef STATS
    node->num_compares++;
#endif

    /*
     * If the match fails, then either use the failure link (if not
     * at the root), or move to the next character since no prefix
     * of any pattern ends with character T[c].
     */
    if (wprime == NULL) {
      if (w == root)
        c++;
      else {
        w = w->faillink;

#ifdef STATS
        node->num_failures++;
#endif
      }
    }
    else {
      /*
       * If we could match the input, move down the tree and to the
       * next input character, and see if that match completes the
       * match to a pattern (when matchid != 0 or outlink != NULL).
       */
      c++;
      w = wprime;

#ifdef STATS
      node->edges_traversed++;
#endif

      if (w->matchid != 0)
        node->output = w;
      else if (w->outlink != NULL) {
        node->output = w->outlink;

#ifdef STATS
        node->outlinks_traversed++;
#endif
      }

      if (node->output != NULL) {
        id = node->output->matchid;
        if (id_out)
          *id_out = id;
        if (length_out)
          *length_out = node->Plengths[id];

        node->w = w;
        node->c = c;

        return &T[c] - node->Plengths[id];
      }
    }
  }

  node->c = c;
  node->endflag = 1;

  return NULL;
}


/*
 * ac_free
 *
 * Free up the allocated AC_STRUCT structure.
 *
 * Parameters:   node  -  a AC_STRUCT structure
 *
 * Returns:  nothing.
 */
void ac_free(AC_STRUCT *node)
{
  AC_TREE front, back, next;

  if (node == NULL)
    return;

  if (node->tree != NULL) {
    front = back = node->tree;
    while (front != NULL) {
      back->sibling = front->children;
      while (back->sibling != NULL)
        back = back->sibling;

      next = front->sibling;
      free(front);
      front = next;
    }
  }

  if (node->Plengths != NULL)
    free(node->Plengths);

  free(node);
}



