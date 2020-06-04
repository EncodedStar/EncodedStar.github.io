---
layout: post
title: "顺序容器"
date: 2020-06-04
description: "顺序容器就是数据结构里的线性表，一共有 5 种：array、vector、deque、list、forward_list"
tag: C++实战笔记
---

{% include JB/setup %}
*  目录
{:toc}

----------

## 顺序容器

<table>
   <tr>
      <td> 连续存储的数组 </td>
	  <td> array、vector 和 deque </td>
   </tr>
   <tr>
      <td> 指针结构的链表 </td>
      <td> list 和 forward_list </td>
   </tr>
</table>

### 连续存储的数组 
- array 与 vector 区别

array 和 vector 直接对应 C 的内置数组，内存布局与 C 完全兼容，所以是开销最低、速度最快的容器。它们两个的区别在于容量能否动态增长。array 是静态数组，大小在初始化的时候就固定了，不能再容纳更多的元素。而 vector 是动态数组，虽然初始化的时候设定了大小，但可以在后面随需增长，容纳任意数量的元素

- deque 与 vector 区别

deque 也是一种可以动态增长的数组，它和 vector 的区别是，它可以在两端高效地插入删除元素，这也是它的名字 double-end queue 的来历，而 vector 则只能用 push_back 在末端追加元素

### 指针结构的链表

- list 和 forward_list 区别

list 是双向链表，可以向前或者向后遍历，而 forward_list，顾名思义，是单向链表，只能向前遍历，查找效率就更低了

### 连续存储的数组和指针结构的链表的区别

vector 和 deque 里的元素因为是连续存储的，所以在中间的插入删除效率就很低，而 list 和 forward_list 是链表结构，插入删除操作只需要调整指针，所以在任意位置的操作都很高效

链表的缺点是查找效率低，只能沿着指针顺序访问，这方面不如 vector 随机访问的效率高

链表结构比起数组结构还有一个缺点，就是存储成本略高，因为必须要为每个元素附加一个或者两个的指针，指向链表的前后节点

### 连续存储的数组和指针结构的链表的扩容机制

vector/deque 和 list/forward_list 都可以动态增长来容纳更多的元素，但它们的内部扩容机制却是不一样的

当 vector 的容量到达上限的时候（capacity），它会再分配一块两倍大小的新内存，然后把旧元素拷贝或者移动过去

这个操作的成本是非常大的，所以，你在使用 vector 的时候最好能够“预估”容量，使用 reserve 提前分配足够的空间，减少动态扩容的拷贝代价

vector 的做法太“激进”，而 deque、list 的的扩容策略就“保守”多了，只会按照固定的“步长”（例如 N 个字节、一个节点）去增加容量。但在短时间内插入大量数据的时候就会频繁分配内存，效果反而不如 vector 一次分配来得好

----------

## 成员函数

### vector 
1. 元素访问
	- at&emsp;访问指定元素，同时进行越界检查
	- operator[]&emsp;访问指定的元素
	- front&emsp;访问第一个元素
	- back&emsp;访问最后一个元素
	- data&emsp;返回指向内存中数组第一个元素的指针
2. 迭代器
	- begin&emsp;返回容器第一个元素的迭代器
	- end&emsp;返回指向容器尾端的迭代器
	- rbegin&emsp;返回指向容器最后元素的逆向迭代器
	- rend&emsp;返回指向前端的逆向迭代器
3. 容量
	- empty&emsp;检查容器是否为空
	- size&emsp;返回容纳元素数
	- max_size&emsp;返回可容纳的最大元素数
4. 操作
	- fill&emsp;以指定值填充容器
	- swap&emsp;交换内容

### list 
1. 元素访问
	- front&emsp;访问第一个元素
	- back&emsp;访问最后一个元素
2. 迭代器
	- begin&emsp;返回指向容器第一元素的迭代器
	- end&emsp;返回指向容器尾端的迭代器
	- rbegin&emsp;返回指向容器尾端的迭代器
	- rend&emsp;返回指向前端的逆向迭代器
3. 容量
	- empty&emsp;检查容器是否为空
	- size&emsp;返回容纳的元素数
	- max_size&emsp;返回可容纳的最大元素数
4. 修改器
	- clear&emsp;清除内容
	- insert&emsp;插入元素
	- emplace&emsp;原位构造元素
	- erase&emsp;擦除元素
	- push_back&emsp;将元素添加到容器末尾
	- emplace_back&emsp;在容器末尾就地构造元素
	- pop_back&emsp;移除末元素
	- push_front&emsp;插入元素到容器起始
	- emplace_front&emsp;在容器头部就地构造元素
	- pop_front&emsp;移除首元素
	- resize&emsp;改变容器中可存储元素的个数
	- swap&emsp;交换内容
5. 操作
	- merge&emsp;合并二个已经排序列表
	- splice&emsp;从另一个list中移动元素
	- remove/remove_if&emsp;移除满足特定标准的元素
	- reverse&emsp;将该链表的所有元素的顺序反转
	- unique&emsp;删除连续的重复元素
	- sort&emsp;对元素进行排序

### queue 
1. 元素访问
	- front&emsp;访问第一个元素
	- back&emsp;访问最后一个元素
2. 容量
	- empty&emsp;检查底层的容器是否为空
	- size&emsp;返回容纳的元素数
3. 修改器
	- push&emsp;像队列尾部插入元素
	- emplace&emsp;于尾部原位构造元素
	- pop&emsp;删除栈顶元素
	- swap&emsp;交换内容

----------

## 扩展

### 链表

**跳表**
- 时间复杂度
    1. 跳表查询的时间复杂度分析：
       - n/2、n/4、n/8、第k级索引结点的个数就是n/(2^k) 假设索引有h级，最高级的索引有2个结点。
       - n/(2^h) = 2，从而求得 h = log2(n) - 1
    2. 时间复杂度 O(logn)

- 优化
	- 升维 ：空间换时间
- 应用
	1. LRU Cache - Linked list: LRU 缓存机制
	2. Redis - Skip LIst
  

### 队列

**双端队列**

  - 简单理解：两端可以进出的
  - 插入和删除都是O(1)操作
  - QueueDeque - double ended queue

**优先队列**

  - 插入操作：O(1)
  - 取出操作：O(logN) - 按照元素的优先级取出
  - 底层具体实现的数据结构较为多样和复杂：heap、bst(二叉搜索树etc)、treap
