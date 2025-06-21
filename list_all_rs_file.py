#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
from pathlib import Path

def format_project_files_to_markdown(root_dir: Path, output_stream):
    """
    遍历指定目录，查找 Cargo.toml 和所有 .rs 文件，
    并将其格式化为 Markdown 输出。

    Args:
        root_dir (Path): 要开始遍历的根目录。
        output_stream: 一个类似文件的对象（如 sys.stdout 或文件句柄），用于写入输出。
    """
    if not root_dir.is_dir():
        print(f"错误：提供的路径 '{root_dir}' 不是一个有效的目录。", file=sys.stderr)
        sys.exit(1)

    files_to_process = []

    # 1. 查找 Cargo.toml 文件
    cargo_toml_path = root_dir / "Cargo.toml"
    if cargo_toml_path.is_file():
        files_to_process.append(cargo_toml_path)

    # 2. 递归查找所有 .rs 文件并排序
    rust_files = sorted(list(root_dir.rglob('*.rs')))
    files_to_process.extend(rust_files)

    if not files_to_process:
        print(f"在 '{root_dir}' 或其子目录中没有找到 Cargo.toml 或 .rs 文件。", file=sys.stderr)
        return

    # 3. 遍历所有找到的文件并格式化输出
    for i, file_path in enumerate(files_to_process):
        try:
            # 获取相对于根目录的路径
            relative_path = file_path.relative_to(root_dir)
            # 统一路径分隔符
            path_str = str(relative_path).replace('\\', '/')

            # 确定 Markdown 代码块的语言标识符
            if file_path.name == 'Cargo.toml':
                lang = 'toml'
            else:
                lang = 'rust'

            # 读取文件内容
            content = file_path.read_text(encoding='utf-8')

            # 在每个文件（除了第一个）前添加一个分隔符
            if i > 0:
                print("\n", file=output_stream)

            # 按照指定格式输出
            print(f"{path_str}", file=output_stream)
            print(f"```{lang}", file=output_stream)
            print(content.rstrip(), file=output_stream)
            print("```", file=output_stream)

        except Exception as e:
            print(f"处理文件 {file_path} 时出错: {e}", file=sys.stderr)

def main():
    """
    主函数，用于解析命令行参数并执行脚本。
    """
    parser = argparse.ArgumentParser(
        description="遍历目录下的 Cargo.toml 和 .rs 文件，并以 Markdown 格式输出其内容。",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="要扫描的 Rust 项目根目录 (默认为当前目录)"
    )
    parser.add_argument(
        "-o", "--output",
        help="将输出写入指定文件，而不是打印到控制台"
    )

    args = parser.parse_args()
    root_directory = Path(args.directory).resolve() # 使用 resolve 获取绝对路径

    if args.output:
        try:
            output_path = Path(args.output)
            # 确保输出目录存在
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                format_project_files_to_markdown(root_directory, f)
            print(f"成功将结果写入文件: {output_path}")
        except IOError as e:
            print(f"错误：无法写入文件 {args.output}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        format_project_files_to_markdown(root_directory, sys.stdout)

if __name__ == "__main__":
    main()
