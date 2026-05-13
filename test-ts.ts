import * as ts from 'web-tree-sitter';

async function test() {
  await ts.Parser.init();
  const parser = new ts.Parser();
  const Bash = await ts.Language.load('./src/tree-sitter-bash.wasm');
  parser.setLanguage(Bash);
  const tree = parser.parse('ls -la');
  console.log(tree.rootNode.toString());
}

test().catch(console.error);
