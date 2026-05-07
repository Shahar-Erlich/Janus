#pragma once
#include <unordered_map>
#include <vector>
#include <queue>
#include <iostream>
#include <sstream>

class AhoCorasick
{
private:
    struct Vertex
    {
        std::unordered_map<char, int> children = {};
        std::vector<int> output_links = {};
        int parent = -1;
        int failure_link = -1;
        char parent_char;
        bool leaf = false;
    };

    /**
     * @brief calculates the suffix (failure) link for a given node
     * @param vertex the vertex ID
     */
    void calcFailureLink(int vertex);

public:
    AhoCorasick();
    AhoCorasick(AhoCorasick &other);
    ~AhoCorasick() = default;
    std::vector<Vertex> _trie;
    int _size;
    int _root;
    std::vector<std::string> _patterns;
    int _word_id;

    /**
     * @brief clear the trie
     */
    void clear();

    /**
     * @brief inserts a new pattern string into the trie and assigns it a unique wordID.
     * @param pattern the string to be inserted
     */
    void addString(const std::string &pattern);

    /**
     * @brief uilds failure links and output link logic for efficient pattern matching.
     */
    void prepare();

    /**
     * @brief Search the given text for all inserted patterns.
     *
     * @param text Text to scan.
     * @return std::optional<std::string> Formatted match summary if at least one
     * pattern was found, or std::nullopt otherwise.
     */
    std::optional<std::string> search(const std::string &text);
};