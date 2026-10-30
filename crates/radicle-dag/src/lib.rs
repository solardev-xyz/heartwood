//! Directed-acyclic graph implementation.
#![warn(missing_docs)]
use std::{
    borrow::Borrow,
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    fmt::Write,
    ops::{ControlFlow, Deref, Index},
};

/// A node in the graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node<K, V> {
    /// The node key.
    pub key: K,
    /// The node value, stored by the user.
    pub value: V,
    /// Nodes depended on.
    pub dependencies: BTreeSet<K>,
    /// Nodes depending on this node.
    pub dependents: BTreeSet<K>,
}

impl<K, V> Node<K, V> {
    fn new(key: K, value: V) -> Self {
        Self {
            key,
            value,
            dependencies: BTreeSet::new(),
            dependents: BTreeSet::new(),
        }
    }
}

impl<K, V> Borrow<V> for &Node<K, V> {
    fn borrow(&self) -> &V {
        &self.value
    }
}

impl<K, V> Deref for Node<K, V> {
    type Target = V;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

/// A directed acyclic graph.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dag<K, V> {
    graph: BTreeMap<K, Node<K, V>>,
    tips: BTreeSet<K>,
    roots: BTreeSet<K>,
}

impl<K: Ord + Copy, V> Dag<K, V> {
    /// Create a new empty DAG.
    pub fn new() -> Self {
        Self {
            graph: BTreeMap::new(),
            tips: BTreeSet::new(),
            roots: BTreeSet::new(),
        }
    }

    /// Create a DAG with a root node.
    pub fn root(key: K, value: V) -> Self {
        Self {
            graph: BTreeMap::from_iter([(key, Node::new(key, value))]),
            tips: BTreeSet::from_iter([key]),
            roots: BTreeSet::from_iter([key]),
        }
    }

    /// Check whether there are any nodes in the graph.
    pub fn is_empty(&self) -> bool {
        self.graph.is_empty()
    }

    /// Return the number of nodes in the graph.
    pub fn len(&self) -> usize {
        self.graph.len()
    }

    /// Add a node to the graph.
    pub fn node(&mut self, key: K, value: V) -> Option<Node<K, V>> {
        self.tips.insert(key);
        self.roots.insert(key);
        self.graph.insert(
            key,
            Node {
                key,
                value,
                dependencies: BTreeSet::new(),
                dependents: BTreeSet::new(),
            },
        )
    }

    /// Add a dependency from one node to the other.
    pub fn dependency(&mut self, from: K, to: K) {
        if let Some(node) = self.graph.get_mut(&from) {
            node.dependencies.insert(to);
            self.roots.remove(&from);
        }
        if let Some(node) = self.graph.get_mut(&to) {
            node.dependents.insert(from);
            self.tips.remove(&to);
        }
    }

    /// Check if the graph contains a node.
    pub fn contains(&self, key: &K) -> bool {
        self.graph.contains_key(key)
    }

    /// Get a node.
    pub fn get(&self, key: &K) -> Option<&Node<K, V>> {
        self.graph.get(key)
    }

    /// Check whether there is a dependency between two nodes.
    pub fn has_dependency(&self, from: &K, to: &K) -> bool {
        self.graph
            .get(from)
            .map(|n| n.dependencies.contains(to))
            .unwrap_or_default()
    }

    /// Get the graph's root nodes, ie. nodes which don't depend on other nodes.
    pub fn roots(&self) -> impl Iterator<Item = (&K, &Node<K, V>)> + '_ {
        self.roots
            .iter()
            .filter_map(|k| self.graph.get(k).map(|n| (k, n)))
    }

    /// Get the graph's tip nodes, ie. nodes which aren't depended on by other nodes.
    pub fn tips(&self) -> impl Iterator<Item = (&K, &Node<K, V>)> + '_ {
        self.tips
            .iter()
            .filter_map(|k| self.graph.get(k).map(|n| (k, n)))
    }

    /// Merge a DAG into this one.
    pub fn merge(&mut self, mut other: Self) {
        let Some((root, _)) = other.roots().next() else {
            return;
        };
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::<K>::from([*root]);

        while let Some(next) = queue.pop_front() {
            if !visited.insert(next) {
                continue;
            }
            if let Some(node) = other.graph.remove(&next) {
                if !self.contains(&next) {
                    self.node(next, node.value);
                }
                for k in &node.dependents {
                    self.dependency(*k, next);
                }
                for k in &node.dependencies {
                    self.dependency(next, *k);
                }
                queue.extend(node.dependents.iter());
            }
        }
    }

    /// Return a topological ordering of the graph's nodes.
    pub fn sorted(&self) -> VecDeque<K> {
        self.sorted_by(Ord::cmp)
    }

    /// Return a topological ordering of the graph's nodes.
    /// Uses a comparison function to sort partially ordered nodes.
    pub fn sorted_by<F>(&self, mut compare: F) -> VecDeque<K>
    where
        F: FnMut(&K, &K) -> Ordering,
    {
        let mut order = VecDeque::new(); // Stores the topological order.
        let mut visited = BTreeSet::new(); // Nodes that have been visited.
        let mut keys = self.graph.keys().collect::<Vec<_>>();

        // The `visit` function builds the list in reverse order, so we counter-act
        // that here.
        keys.sort_by(|a, b| compare(a, b).reverse());

        for node in keys {
            self.visit(node, &mut visited, &mut order);
        }
        order
    }

    /// Fold over the graph in topological order, pruning branches along the way.
    /// This is a depth-first traversal.
    ///
    /// To continue traversing a branch, return [`ControlFlow::Continue`] from the
    /// filter function. To stop traversal of a branch and prune it,
    /// return [`ControlFlow::Break`].
    pub fn prune<F>(&mut self, roots: &[K], filter: F)
    where
        F: for<'r> FnMut(
            &'r K,
            &'r Node<K, V>,
            Box<dyn Iterator<Item = (&'r K, &'r Node<K, V>)> + 'r>,
        ) -> ControlFlow<()>,
    {
        self.prune_by(roots, filter, |(k1, _), (k2, _)| k1.cmp(k2))
    }

    /// Fold over the graph in the order provided by `order`, pruning branches
    /// along the way.
    /// This is a depth-first traversal.
    ///
    /// To continue traversing a branch, return [`ControlFlow::Continue`] from the
    /// filter function. To stop traversal of a branch and prune it,
    /// return [`ControlFlow::Break`].
    pub fn prune_by<F, P>(&mut self, roots: &[K], mut filter: F, ordering: P)
    where
        F: for<'r> FnMut(
            &'r K,
            &'r Node<K, V>,
            Box<dyn Iterator<Item = (&'r K, &'r Node<K, V>)> + 'r>,
        ) -> ControlFlow<()>,
        P: Fn((&K, &V), (&K, &V)) -> Ordering,
    {
        let mut visited = BTreeSet::new();
        let mut result = VecDeque::new();

        for root in roots {
            self.visit_by(root, &mut visited, &mut result, &ordering);
        }

        for next in result {
            if let Some(node) = self.graph.get(&next) {
                let siblings = self
                    .siblings_of(node)
                    .filter_map(|k| self.graph.get(k))
                    .map(|node| (&node.key, node));

                match filter(&next, node, Box::new(siblings)) {
                    ControlFlow::Continue(()) => {}
                    ControlFlow::Break(()) => {
                        // When pruning a node, we remove all transitive dependents on
                        // that node.
                        self.remove(&next);
                    }
                }
            }
        }
    }

    /// Fold over the graph in topological order, skipping certain branches.
    /// This is a depth-first traversal.
    ///
    /// To continue traversing a branch, return [`ControlFlow::Continue`] from the
    /// filter function. To stop traversal of a branch, return [`ControlFlow::Break`].
    pub fn fold<A, F>(&self, roots: &[K], mut acc: A, mut filter: F) -> A
    where
        F: for<'r> FnMut(A, &'r K, &'r Node<K, V>) -> ControlFlow<A, A>,
    {
        let mut visited = BTreeSet::new();
        let mut result = VecDeque::new();
        let mut skip = BTreeSet::new();

        assert!(
            roots.windows(2).all(|w| w[0] < w[1]),
            "The roots must be sorted in ascending order"
        );

        for root in roots.iter().rev() {
            self.visit(root, &mut visited, &mut result);
        }

        for next in result {
            if skip.contains(&next) {
                continue;
            }
            if let Some(node) = self.graph.get(&next) {
                match filter(acc, &next, node) {
                    ControlFlow::Continue(a) => {
                        acc = a;
                    }
                    ControlFlow::Break(a) => {
                        // When filtering out a node, we filter out all transitive dependents on
                        // that node by adding them to the already visited list.
                        skip.extend(self.descendants_of(node));

                        acc = a;
                    }
                }
            }
        }
        acc
    }

    /// Remove a node from the graph, and all its dependents.
    ///
    /// Its transitive dependents are removed without recursion, so that a
    /// history as long as a peer makes it can't exhaust the stack (Security
    /// R-20): depth-first, in the order the recursive removal took them.
    pub fn remove(&mut self, key: &K) -> Option<Node<K, V>> {
        let node = self.graph.remove(key)?;
        self.detach(key, &node);
        let mut stack: Vec<K> = node.dependents.iter().rev().copied().collect();
        while let Some(k) = stack.pop() {
            if let Some(dependent) = self.graph.remove(&k) {
                self.detach(&k, &dependent);
                stack.extend(dependent.dependents.iter().rev().copied());
            }
        }
        Some(node)
    }

    /// Detaches `node`, just taken out of the graph under `key`, from the
    /// tips, the roots and its dependencies. A dependency left with no
    /// dependent becomes a tip.
    fn detach(&mut self, key: &K, node: &Node<K, V>) {
        self.tips.remove(key);
        self.roots.remove(key);

        for k in &node.dependencies {
            if let Some(dependency) = self.graph.get_mut(k) {
                dependency.dependents.remove(key);

                if dependency.dependents.is_empty() {
                    self.tips.insert(*k);
                }
            }
        }
    }

    fn descendants_of(&self, from: &Node<K, V>) -> Vec<K> {
        let mut visited = BTreeSet::new();
        let mut stack = VecDeque::new();
        let mut nodes = Vec::new();

        stack.extend(from.dependents.iter());

        while let Some(key) = stack.pop_front() {
            if let Some(node) = self.graph.get(&key)
                && visited.insert(key)
            {
                nodes.push(key);

                for &neighbour in &node.dependents {
                    stack.push_back(neighbour);
                }
            }
        }
        nodes
    }

    fn ancestors_of(&self, from: &Node<K, V>) -> Vec<K> {
        let mut visited = BTreeSet::new();
        let mut stack = VecDeque::new();
        let mut nodes = Vec::new();

        stack.extend(from.dependencies.iter());

        while let Some(key) = stack.pop_front() {
            if let Some(node) = self.graph.get(&key)
                && visited.insert(key)
            {
                nodes.push(key);

                for &neighbour in &node.dependencies {
                    stack.push_back(neighbour);
                }
            }
        }
        nodes
    }

    /// Get the nodes that are neither an ancestor nor a descendant of the given node.
    fn siblings_of(&self, node: &Node<K, V>) -> impl Iterator<Item = &K> {
        let ancestors = self.ancestors_of(node);
        let descendants = self.descendants_of(node);
        let key = node.key;

        self.graph
            .keys()
            .filter(move |k| !ancestors.contains(k) && !descendants.contains(k) && **k != key)
    }

    /// Add nodes to the topological order, starting from the given node: each
    /// node's dependents first, in reverse, then the node, at the front.
    fn visit(&self, key: &K, visited: &mut BTreeSet<K>, order: &mut VecDeque<K>) {
        self.depth_first(key, visited, order, |node| {
            node.dependents.iter().rev().copied().collect()
        });
    }

    /// Add nodes to the provided ordering, starting from the given node: each
    /// node's dependents first, those in the graph, in reverse of `ordering`,
    /// then the node, at the front.
    fn visit_by(
        &self,
        key: &K,
        visited: &mut BTreeSet<K>,
        order: &mut VecDeque<K>,
        ordering: &impl Fn((&K, &V), (&K, &V)) -> Ordering,
    ) {
        self.depth_first(key, visited, order, |node| {
            let mut dependents: Vec<&Node<K, V>> = node
                .dependents
                .iter()
                .filter_map(|k| self.get(k))
                .collect::<Vec<_>>();
            dependents.sort_by(|x, y| ordering((&x.key, &x.value), (&y.key, &y.value)));
            dependents.iter().rev().map(|node| node.key).collect()
        });
    }

    /// A depth-first walk from `key`, with an explicit stack rather than
    /// recursion, so that a graph as deep as a peer makes it can't overflow
    /// the thread's stack. Each node is visited once, its `children` in
    /// their order, and put at the front of `order` once they all have been,
    /// exactly as a recursive walk would. A key not in the graph has no
    /// children.
    fn depth_first(
        &self,
        key: &K,
        visited: &mut BTreeSet<K>,
        order: &mut VecDeque<K>,
        children: impl Fn(&Node<K, V>) -> Vec<K>,
    ) {
        let children_of = |key: &K| self.graph.get(key).map(&children).unwrap_or_default();
        if !visited.insert(*key) {
            return;
        }
        let mut stack = vec![(*key, children_of(key), 0)];
        while let Some((key, kids, next)) = stack.last_mut() {
            if let Some(child) = kids.get(*next).copied() {
                *next += 1;
                if visited.insert(child) {
                    stack.push((child, children_of(&child), 0));
                }
            } else {
                order.push_front(*key);
                stack.pop();
            }
        }
    }
}

impl<K: Ord + Copy + fmt::Display, V> Dag<K, V> {
    /// Return the graph in "dot" format.
    pub fn to_dot(&self) -> String {
        let mut output = String::new();

        writeln!(output, "digraph G {{").ok();
        for (k, v) in self.graph.iter() {
            for d in &v.dependencies {
                writeln!(output, "\t\"{k}\" -> \"{d}\";").ok();
            }
        }
        writeln!(output, "}}").ok();

        output
    }
}

impl<K: Ord + Copy + fmt::Debug, V> Index<&K> for Dag<K, V> {
    type Output = Node<K, V>;

    fn index(&self, key: &K) -> &Self::Output {
        self.get(key)
            .unwrap_or_else(|| panic!("Dag::index: node {key:?} not found in graph"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The recursive walks the iterative ones replace, as the reference
    /// order.
    fn visit_recursively<K: Ord + Copy, V>(
        dag: &Dag<K, V>,
        key: &K,
        visited: &mut BTreeSet<K>,
        order: &mut VecDeque<K>,
    ) {
        if visited.insert(*key) {
            if let Some(node) = dag.graph.get(key) {
                for dependent in node.dependents.iter().rev() {
                    visit_recursively(dag, dependent, visited, order);
                }
            }
            order.push_front(*key);
        }
    }

    fn visit_by_recursively<K: Ord + Copy, V>(
        dag: &Dag<K, V>,
        key: &K,
        visited: &mut BTreeSet<K>,
        order: &mut VecDeque<K>,
        ordering: &impl Fn((&K, &V), (&K, &V)) -> Ordering,
    ) {
        if visited.insert(*key) {
            if let Some(node) = dag.graph.get(key) {
                let mut dependents: Vec<&Node<K, V>> =
                    node.dependents.iter().filter_map(|k| dag.get(k)).collect();
                dependents.sort_by(|x, y| ordering((&x.key, &x.value), (&y.key, &y.value)));
                for dependent in dependents.iter().rev() {
                    visit_by_recursively(dag, &dependent.key, visited, order, ordering);
                }
            }
            order.push_front(*key);
        }
    }

    /// The recursive removal the iterative one replaces, as the reference.
    fn remove_recursively<K: Ord + Copy, V>(dag: &mut Dag<K, V>, key: &K) -> Option<Node<K, V>> {
        if let Some(node) = dag.graph.remove(key) {
            dag.tips.remove(key);
            dag.roots.remove(key);

            for k in &node.dependencies {
                if let Some(dependency) = dag.graph.get_mut(k) {
                    dependency.dependents.remove(key);

                    if dependency.dependents.is_empty() {
                        dag.tips.insert(*k);
                    }
                }
            }
            for k in &node.dependents {
                remove_recursively(dag, k);
            }
            Some(node)
        } else {
            None
        }
    }

    /// A random graph of up to 60 nodes, each depending on up to three
    /// before it, with random values.
    fn random(rng: &mut fastrand::Rng) -> (Dag<u32, u8>, u32) {
        let mut dag = Dag::new();
        let len = rng.u32(1..60);
        for i in 0..len {
            dag.node(i, rng.u8(..));
        }
        for i in 1..len {
            for _ in 0..rng.usize(0..4) {
                dag.dependency(i, rng.u32(0..i));
            }
        }
        (dag, len)
    }

    #[test]
    // Review of heartwood #21, round 1: the iterative removal returns the node
    // the recursive one did, and leaves exactly the graph it did, its nodes,
    // their dependencies and dependents, its tips and its roots, on random
    // graphs, one removal after another.
    fn removal_keeps_the_recursive_result() {
        let mut rng = fastrand::Rng::with_seed(0x7e40);
        for _ in 0..500 {
            let (mut dag, len) = random(&mut rng);
            let mut expected = dag.clone();
            for _ in 0..rng.usize(1..4) {
                // Keys the graph doesn't hold remove nothing.
                let key = rng.u32(0..len + 3);
                assert_eq!(dag.remove(&key), remove_recursively(&mut expected, &key));
                assert_eq!(dag, expected);
            }
        }
    }

    #[test]
    // The iterative walks visit every node in exactly the order the recursive
    // ones did, on random graphs: from each start, and in sequence.
    fn the_walks_keep_the_recursive_order() {
        let mut rng = fastrand::Rng::with_seed(0x5eed);
        for _ in 0..500 {
            let mut dag = Dag::new();
            let len = rng.u32(1..60);
            for i in 0..len {
                dag.node(i, rng.u8(..));
            }
            for i in 1..len {
                for _ in 0..rng.usize(0..4) {
                    dag.dependency(i, rng.u32(0..i));
                }
            }
            // Keys the graph doesn't hold are walked as leaves.
            let starts: Vec<u32> = (0..rng.usize(1..6)).map(|_| rng.u32(0..len + 3)).collect();
            let ordering =
                |(k1, v1): (&u32, &u8), (k2, v2): (&u32, &u8)| v1.cmp(v2).then(k1.cmp(k2));

            let (mut visited, mut order) = (BTreeSet::new(), VecDeque::new());
            let (mut seen, mut expected) = (BTreeSet::new(), VecDeque::new());
            for start in &starts {
                dag.visit(start, &mut visited, &mut order);
                visit_recursively(&dag, start, &mut seen, &mut expected);
            }
            assert_eq!(order, expected);
            assert_eq!(visited, seen);

            let (mut visited, mut order) = (BTreeSet::new(), VecDeque::new());
            let (mut seen, mut expected) = (BTreeSet::new(), VecDeque::new());
            for start in &starts {
                dag.visit_by(start, &mut visited, &mut order, &ordering);
                visit_by_recursively(&dag, start, &mut seen, &mut expected, &ordering);
            }
            assert_eq!(order, expected);
            assert_eq!(visited, seen);
        }
    }

    /// A chain of `len` nodes, each depending on the one before.
    fn chain(len: u32) -> Dag<u32, ()> {
        let mut dag = Dag::new();
        for i in 0..len {
            dag.node(i, ());
            if i > 0 {
                dag.dependency(i, i - 1);
            }
        }
        dag
    }

    #[test]
    // Security R-20: a history as long as a peer makes it is walked without
    // recursion. Each walk finishes on a 256 KiB stack, where the recursive
    // walks overflowed it and aborted the process.
    fn a_long_chain_is_walked_without_recursion() {
        const LEN: u32 = 100_000;
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| {
                let dag = chain(LEN);
                assert_eq!(dag.sorted().len(), LEN as usize);
                assert_eq!(
                    dag.fold(&[0], 0, |n, _, _| ControlFlow::Continue(n + 1)),
                    LEN
                );
                // `prune_by`'s walk, on its own: its siblings cost grows with
                // the square of the history, so the whole prune runs on a
                // shorter chain below.
                let (mut visited, mut order) = (BTreeSet::new(), VecDeque::new());
                dag.visit_by(&0, &mut visited, &mut order, &|(a, _), (b, _)| a.cmp(b));
                assert_eq!(order.len(), LEN as usize);
                assert!(order.iter().copied().eq(0..LEN));

                let mut dag = chain(5_000);
                let mut seen = 0;
                dag.prune(&[0], |_, _, _| {
                    seen += 1;
                    ControlFlow::Continue(())
                });
                assert_eq!(seen, 5_000);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    // Review of heartwood #21, round 1: removing a node removes its
    // transitive dependents without recursion, directly and through
    // `prune_by`'s `Break`, on a 256 KiB stack, where the recursive removal
    // overflowed it.
    fn a_long_chain_is_removed_without_recursion() {
        const LEN: u32 = 100_000;
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| {
                let mut dag = chain(LEN);
                let removed = dag.remove(&1).unwrap();
                assert_eq!(removed.key, 1);
                assert_eq!(dag.len(), 1);
                assert_eq!(dag.tips().map(|(k, _)| *k).collect::<Vec<_>>(), [0]);
                assert_eq!(dag.roots().map(|(k, _)| *k).collect::<Vec<_>>(), [0]);
                assert!(dag.get(&0).unwrap().dependents.is_empty());

                // A bad change near the start of a long history: the rest of
                // it is pruned with it.
                let mut dag = chain(LEN);
                let mut seen = Vec::new();
                dag.prune(&[0], |key, _, _| {
                    seen.push(*key);
                    if *key == 1 {
                        ControlFlow::Break(())
                    } else {
                        ControlFlow::Continue(())
                    }
                });
                assert_eq!(seen, [0, 1]);
                assert_eq!(dag.len(), 1);
                assert_eq!(dag.tips().map(|(k, _)| *k).collect::<Vec<_>>(), [0]);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_len() {
        let mut dag = Dag::new();

        dag.node(0, ());
        dag.node(1, ());
        dag.node(2, ());

        assert_eq!(dag.len(), 3);
    }

    #[test]
    fn test_is_empty() {
        let mut dag = Dag::new();
        assert!(dag.is_empty());

        dag.node(0, ());
        assert!(!dag.is_empty());
    }

    #[test]
    fn test_dependencies() {
        let mut dag = Dag::new();

        dag.node(0, ());
        dag.node(1, ());
        dag.dependency(0, 1);

        assert!(dag.has_dependency(&0, &1));
        assert!(!dag.has_dependency(&1, &0));
    }

    #[test]
    fn test_get() {
        let mut dag = Dag::new();

        dag.node(0, "rad");
        dag.node(1, "dar");

        assert_eq!(dag[&0].value, "rad");
        assert_eq!(dag[&1].value, "dar");
        assert!(dag.get(&2).is_none());
    }

    #[test]
    fn test_cycle() {
        let mut dag = Dag::new();

        dag.node(0, ());
        dag.node(1, ());

        dag.dependency(0, 1);
        dag.dependency(1, 0);

        let mut sorted = dag.sorted();
        let expected: &[&[i32]] = &[&[0, 1], &[1, 0]];

        assert!(expected.contains(&&*sorted.make_contiguous()));
    }

    #[test]
    fn test_merge_1() {
        let mut a = Dag::new();
        let mut b = Dag::new();
        let mut c = Dag::new();

        a.node(0, ());
        a.node(1, ());
        a.dependency(1, 0);

        b.node(0, ());
        b.node(2, ());
        b.dependency(2, 0);

        c.merge(a);
        c.merge(b);

        assert!(c.get(&0).is_some());
        assert!(c.get(&1).is_some());
        assert!(c.get(&2).is_some());
        assert!(c.has_dependency(&1, &0));
        assert!(c.has_dependency(&2, &0));
    }

    #[test]
    fn test_merge_2() {
        let mut a = Dag::new();
        let mut b = Dag::new();

        a.node(0, ());
        a.node(1, ());
        a.node(2, ());
        a.dependency(1, 0);
        a.dependency(2, 0);

        b.node(0, ());
        b.node(1, ());
        b.node(2, ());
        b.node(3, ());
        b.node(4, ());
        b.dependency(1, 0);
        b.dependency(2, 0);
        b.dependency(3, 0);
        b.dependency(4, 2);

        assert!(a.tips.contains(&2));

        a.merge(b);

        assert!(a.get(&0).is_some());
        assert!(a.get(&1).is_some());
        assert!(a.get(&2).is_some());
        assert!(a.get(&3).is_some());
        assert!(a.get(&4).is_some());
        assert!(a.has_dependency(&4, &2));
        assert!(a.get(&2).unwrap().dependents.contains(&4));
        assert!(a.get(&0).unwrap().dependents.contains(&3));
        assert!(a.tips.contains(&1));
        assert!(!a.tips.contains(&2));
        assert!(a.tips.contains(&3));
        assert!(a.tips.contains(&4));
        assert!(a.roots.contains(&0));
    }

    #[test]
    fn test_diamond() {
        let mut dag = Dag::new();

        dag.node(0, ());
        dag.node(1, ());
        dag.node(2, ());
        dag.node(3, ());

        dag.dependency(1, 0);
        dag.dependency(2, 0);
        dag.dependency(3, 1);
        dag.dependency(3, 2);

        assert_eq!(dag.tips().map(|(k, _)| *k).collect::<Vec<_>>(), vec![3]);
        assert_eq!(dag.roots().map(|(k, _)| *k).collect::<Vec<_>>(), vec![0]);

        // All of the possible sort orders for the above graph.
        let expected: &[&[i32]] = &[&[0, 1, 2, 3], &[0, 2, 1, 3]];
        let mut actual = dag.sorted();

        assert!(expected.contains(&&*actual.make_contiguous()), "{actual:?}");
    }

    #[test]
    fn test_complex() {
        let mut dag = Dag::new();

        dag.node(0, ());
        dag.node(1, ());
        dag.node(2, ());
        dag.node(3, ());
        dag.node(4, ());
        dag.node(5, ());

        dag.dependency(3, 2);
        dag.dependency(1, 3);
        dag.dependency(2, 5);
        dag.dependency(0, 5);
        dag.dependency(0, 4);
        dag.dependency(1, 4);

        assert_eq!(
            dag.tips().map(|(k, _)| *k).collect::<BTreeSet<_>>(),
            BTreeSet::from_iter([1, 0])
        );
        assert_eq!(
            dag.roots().map(|(k, _)| *k).collect::<BTreeSet<_>>(),
            BTreeSet::from_iter([4, 5])
        );

        // All of the possible sort orders for the above graph.
        let expected = &[
            [4, 5, 0, 2, 3, 1],
            [4, 5, 2, 0, 3, 1],
            [4, 5, 2, 3, 0, 1],
            [4, 5, 2, 3, 1, 0],
            [5, 2, 3, 4, 0, 1],
            [5, 2, 3, 4, 1, 0],
            [5, 2, 4, 0, 3, 1],
            [5, 2, 4, 3, 0, 1],
            [5, 2, 4, 3, 1, 0],
            [5, 4, 0, 2, 3, 1],
            [5, 4, 2, 0, 3, 1],
            [5, 4, 2, 3, 0, 1],
            [5, 4, 2, 3, 1, 0],
        ];
        let mut sorts = BTreeSet::new();
        let mut rng = fastrand::Rng::new();

        while sorts.len() < expected.len() {
            sorts.insert(
                dag.sorted_by(|a, b| if rng.bool() { a.cmp(b) } else { b.cmp(a) })
                    .make_contiguous()
                    .to_vec(),
            );
        }
        for e in expected {
            assert!(sorts.remove(e.to_vec().as_slice()));
        }
        assert!(sorts.is_empty());
    }

    #[test]
    fn test_fold_sorting_1() {
        let mut dag = Dag::new();

        dag.node("R", ());
        dag.node("A1", ());
        dag.node("A2", ());
        dag.node("A3", ());
        dag.node("B1", ());
        dag.node("B2", ());
        dag.node("B3", ());
        dag.node("C1", ());

        dag.dependency("A1", "R");
        dag.dependency("A2", "R");
        dag.dependency("A3", "R");

        dag.dependency("B1", "A1");
        dag.dependency("B2", "A1");
        dag.dependency("B3", "A2");
        dag.dependency("B3", "A3");

        dag.dependency("C1", "B1");
        dag.dependency("C1", "B2");
        dag.dependency("C1", "B3");

        let acc = dag.fold(&["R"], Vec::new(), |mut acc, key, _| {
            acc.push(*key);
            ControlFlow::Continue(acc)
        });
        assert_eq!(acc, vec!["R", "A1", "B1", "B2", "A2", "A3", "B3", "C1"]);
    }

    #[test]
    fn test_fold_sorting_2() {
        let mut dag = Dag::new();

        dag.node("R", ());
        dag.node("A1", ());
        dag.node("A2", ());
        dag.node("A3", ());
        dag.node("B1", ());
        dag.node("C1", ());
        dag.node("C2", ());
        dag.node("C3", ());

        dag.dependency("A1", "R");
        dag.dependency("A2", "A1");
        dag.dependency("A3", "A2");

        dag.dependency("B1", "R");

        dag.dependency("C1", "B1");
        dag.dependency("C1", "A3");
        dag.dependency("C2", "B1");
        dag.dependency("C2", "A3");
        dag.dependency("C3", "B1");
        dag.dependency("C3", "A3");

        let acc = dag.fold(&["R"], Vec::new(), |mut acc, key, _| {
            acc.push(*key);
            ControlFlow::Continue(acc)
        });

        assert_eq!(acc, vec!["R", "A1", "A2", "A3", "B1", "C1", "C2", "C3"]);
        assert_eq!(dag.sorted(), acc);
    }

    #[test]
    fn test_fold_diamond() {
        let mut dag = Dag::new();

        dag.node("R", ());
        dag.node("A1", ());
        dag.node("A2", ());
        dag.node("B", ());

        dag.dependency("A1", "R");
        dag.dependency("A2", "R");
        dag.dependency("B", "A1");
        dag.dependency("B", "A2");

        let acc = dag.fold(&["R"], Vec::new(), |mut acc, key, _| {
            acc.push(*key);
            ControlFlow::Continue(acc)
        });
        assert_eq!(acc, vec!["R", "A1", "A2", "B"]);

        let sorted = dag.sorted();
        assert_eq!(sorted, acc);
    }

    #[test]
    fn test_fold_multiple_roots() {
        let mut dag = Dag::new();

        dag.node("R", ());
        dag.node("A1", ());
        dag.node("A2", ());

        dag.dependency("A1", "R");
        dag.dependency("A2", "R");

        let acc = dag.fold(&["A1", "A2"], Vec::new(), |mut acc, key, _| {
            acc.push(*key);
            ControlFlow::Continue(acc)
        });
        assert_eq!(acc, &["A1", "A2"]);
    }

    #[test]
    fn test_fold_reject() {
        let mut dag = Dag::new();

        dag.node("R", ());
        dag.node("A1", ());
        dag.node("A2", ());
        dag.node("B1", ());
        dag.node("C1", ());
        dag.node("D1", ());

        dag.dependency("A1", "R");
        dag.dependency("A2", "R");
        dag.dependency("B1", "A1");
        dag.dependency("C1", "B1");
        dag.dependency("D1", "C1");
        dag.dependency("D1", "A2");

        let a1 = dag.get(&"A1").unwrap();
        assert_eq!(dag.descendants_of(a1), vec!["B1", "C1", "D1"]);

        let acc = dag.fold(&["R"], Vec::new(), |mut acc, key, _| {
            if *key == "A1" {
                ControlFlow::Break(acc)
            } else {
                acc.push(*key);
                ControlFlow::Continue(acc)
            }
        });
        assert_eq!(acc, vec!["R", "A2"]);

        let acc = dag.fold(&["R"], Vec::new(), |mut acc, key, _| {
            if *key == "A2" {
                ControlFlow::Break(acc)
            } else {
                acc.push(*key);
                ControlFlow::Continue(acc)
            }
        });
        assert_eq!(acc, vec!["R", "A1", "B1", "C1"]);
    }

    #[test]
    fn test_remove() {
        let mut dag = Dag::new();

        dag.node("R", ());
        dag.node("A1", ());
        dag.node("A2", ());
        dag.node("A3", ());
        dag.node("B1", ());
        dag.node("C1", ());
        dag.node("D1", ());

        dag.dependency("A1", "R");
        dag.dependency("A2", "R");
        dag.dependency("A3", "A2");
        dag.dependency("B1", "A1");
        dag.dependency("B1", "A2");
        dag.dependency("C1", "B1");
        dag.dependency("C1", "A3");
        dag.dependency("D1", "C1");
        dag.dependency("D1", "A2");

        dag.remove(&"C1");
        assert!(dag.get(&"C1").is_none());
        assert!(dag.get(&"D1").is_none());
        assert!(!dag.tips.contains(&"D1"));
        assert_eq!(dag.tips.iter().collect::<Vec<_>>(), vec![&"A3", &"B1"]);

        dag.remove(&"A3");
        assert_eq!(dag.tips.iter().collect::<Vec<_>>(), vec![&"B1"]);

        dag.remove(&"A1");
        assert!(dag.get(&"A1").is_none());
        assert!(dag.get(&"B1").is_none());
        assert!(dag.get(&"A2").is_some());
        assert_eq!(dag.tips.iter().collect::<Vec<_>>(), vec![&"A2"]);

        dag.remove(&"R");
        assert!(dag.is_empty());
        assert!(dag.tips.is_empty());
        assert!(dag.roots.is_empty());
    }

    #[test]
    fn test_prune_1() {
        let mut dag = Dag::new();

        dag.node("R", ());
        dag.node("A1", ());
        dag.node("A2", ());
        dag.node("B1", ());
        dag.node("C1", ());
        dag.node("D1", ());

        dag.dependency("A1", "R");
        dag.dependency("A2", "R");
        dag.dependency("B1", "A1");
        dag.dependency("C1", "B1");
        dag.dependency("D1", "C1");
        dag.dependency("D1", "A2");

        let a1 = dag.get(&"A1").unwrap();
        assert_eq!(dag.descendants_of(a1), vec!["B1", "C1", "D1"]);

        dag.prune(&["R"], |key, _, _| {
            if key == &"B1" {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        });
        assert_eq!(dag.sorted(), vec!["R", "A1", "A2"]);
    }

    #[test]
    fn test_siblings() {
        let mut dag = Dag::new();

        dag.node("R", ());
        dag.node("A1", ());
        dag.node("A2", ());
        dag.node("A3", ());
        dag.node("A4", ());
        dag.node("B1", ());
        dag.node("C1", ());
        dag.node("C2", ());
        dag.node("C3", ());

        dag.dependency("A1", "R");
        dag.dependency("A2", "A1");
        dag.dependency("A3", "A2");

        dag.dependency("B1", "A2");

        dag.dependency("C1", "R");
        dag.dependency("C2", "C1");
        dag.dependency("C3", "C2");

        dag.dependency("A4", "B1");
        dag.dependency("A4", "C3");
        dag.dependency("A4", "A3");

        let siblings: Vec<_> = dag.siblings_of(dag.get(&"A3").unwrap()).copied().collect();
        assert_eq!(siblings, vec!["B1", "C1", "C2", "C3"]);

        let siblings: Vec<_> = dag.siblings_of(dag.get(&"A4").unwrap()).copied().collect();
        assert_eq!(siblings, Vec::<&str>::new());

        let siblings: Vec<_> = dag.siblings_of(dag.get(&"C1").unwrap()).copied().collect();
        assert_eq!(siblings, vec!["A1", "A2", "A3", "B1"]);

        let siblings: Vec<_> = dag.siblings_of(dag.get(&"C2").unwrap()).copied().collect();
        assert_eq!(siblings, vec!["A1", "A2", "A3", "B1"]);

        let siblings: Vec<_> = dag.siblings_of(dag.get(&"B1").unwrap()).copied().collect();
        assert_eq!(siblings, vec!["A3", "C1", "C2", "C3"]);

        let siblings: Vec<_> = dag.siblings_of(dag.get(&"R").unwrap()).copied().collect();
        assert_eq!(siblings, Vec::<&str>::new());
    }

    #[test]
    fn test_prune_2() {
        let mut dag = Dag::new();

        dag.node("R", ());
        dag.node("A1", ());
        dag.node("A2", ());
        dag.node("A3", ());
        dag.node("B1", ());
        dag.node("C1", ());
        dag.node("C2", ());
        dag.node("C3", ());

        dag.dependency("A1", "R");
        dag.dependency("A2", "A1");
        dag.dependency("A3", "A2");

        dag.dependency("B1", "R");

        dag.dependency("C1", "B1");
        dag.dependency("C1", "A3");
        dag.dependency("C2", "B1");
        dag.dependency("C2", "A3");
        dag.dependency("C3", "B1");
        dag.dependency("C3", "A3");

        let mut order = VecDeque::new();

        dag.prune(&["R"], |key, _, _| {
            order.push_back(*key);
            ControlFlow::Continue(())
        });
        assert_eq!(order, dag.sorted());
    }

    #[test]
    fn test_prune_by_sorting() {
        let mut dag = Dag::new();

        dag.node("R", 0);
        dag.node("A1", 1);
        dag.node("A2", 2);
        dag.node("A3", 3);
        dag.node("B1", 1);
        dag.node("B2", 2);
        dag.node("B3", 3);
        dag.node("C1", 1);

        dag.dependency("A1", "R");
        dag.dependency("A2", "R");
        dag.dependency("A3", "R");

        dag.dependency("B1", "A1");
        dag.dependency("B2", "A1");
        dag.dependency("B3", "A2");
        dag.dependency("B3", "A3");

        dag.dependency("C1", "B1");
        dag.dependency("C1", "B2");
        dag.dependency("C1", "B3");

        let mut order = Vec::new();
        dag.prune_by(
            &["R"],
            |key, _, _| {
                order.push(*key);
                ControlFlow::Continue(())
            },
            |(a, _), (b, _)| a.cmp(b),
        );
        assert_eq!(order, vec!["R", "A1", "B1", "B2", "A2", "A3", "B3", "C1"]);

        let mut order = Vec::new();
        dag.prune_by(
            &["R"],
            |key, _, _| {
                order.push(*key);
                ControlFlow::Continue(())
            },
            |(a, _), (b, _)| a.cmp(b).reverse(),
        );
        assert_eq!(order, vec!["R", "A3", "A2", "B3", "A1", "B2", "B1", "C1"]);

        let mut order = Vec::new();
        dag.prune_by(
            &["R"],
            |key, _, _| {
                order.push(*key);
                ControlFlow::Continue(())
            },
            |(_, a), (_, b)| a.cmp(b).reverse(),
        );
        assert_eq!(order, vec!["R", "A3", "A2", "B3", "A1", "B2", "B1", "C1"]);
    }

    #[test]
    fn test_contains() {
        let mut dag = Dag::<u8, ()>::new();

        assert!(!dag.contains(&0));

        dag.node(0, ());
        dag.node(1, ());
        dag.dependency(0, 1);
        dag.node(2, ());
        dag.dependency(2, 1);
        dag.dependency(2, 0);
        dag.node(3, ());

        for i in 0..4 {
            assert!(dag.contains(&i));
        }
        assert!(!dag.contains(&4));
    }
}
