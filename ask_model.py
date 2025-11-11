#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def get_model_info():
    """返回模型信息"""
    return {
        "greeting": "你好！",
        "model": "Claude",
        "developer": "Anthropic",
        "description": "我是 Claude，由 Anthropic 开发的 AI 助手。"
    }

def main():
    info = get_model_info()
    print(info["greeting"])
    print(f"我是 {info['model']}，由 {info['developer']} 开发的 AI 助手。")

if __name__ == "__main__":
    main()
