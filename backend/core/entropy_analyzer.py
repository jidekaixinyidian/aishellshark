# -*- coding: utf-8 -*-
"""
熵值分析模块
Shannon 熵计算、高熵流量标记、AES 块对齐检测
"""

import math
from collections import Counter
from typing import Optional, List, Tuple
from loguru import logger


class EntropyAnalyzer:
    """
    Shannon 熵分析器
    用于检测加密/混淆流量
    """

    def __init__(self, config: dict):
        self.entropy_threshold = config.get("entropy_threshold", 7.0)
        self.aes_block_size = config.get("aes_block_size", 16)

    def calculate_entropy(self, data: bytes) -> float:
        """
        计算 Shannon 熵
        熵值范围：0（完全规律）到 8（完全随机）
        加密数据通常熵值 > 7.0
        """
        if not data:
            return 0.0

        # 统计每个字节的出现频率
        byte_counts = Counter(data)
        total = len(data)

        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                probability = count / total
                entropy -= probability * math.log2(probability)

        return entropy

    def calculate_string_entropy(self, text: str) -> float:
        """计算字符串的 Shannon 熵"""
        if not text:
            return 0.0

        char_counts = Counter(text)
        total = len(text)

        entropy = 0.0
        for count in char_counts.values():
            if count > 0:
                probability = count / total
                entropy -= probability * math.log2(probability)

        return entropy

    def is_high_entropy(self, data: bytes) -> bool:
        """判断数据是否为高熵（可能为加密数据）"""
        entropy = self.calculate_entropy(data)
        return entropy > self.entropy_threshold

    def check_aes_alignment(self, data: bytes) -> bool:
        """
        检测数据是否符合 AES 块对齐
        AES 加密数据长度通常是 16 字节的倍数
        """
        if not data:
            return False

        # 检查数据长度是否为 16 的倍数
        if len(data) % self.aes_block_size != 0:
            return False

        # 数据长度至少为 32 字节（2 个 AES 块）
        if len(data) < 32:
            return False

        # 检查熵值是否足够高（加密数据）
        entropy = self.calculate_entropy(data)
        if entropy < 6.5:
            return False

        return True

    def analyze_blocks(self, data: bytes, block_size: int = 16) -> dict:
        """
        分块分析数据熵值
        用于检测部分加密的数据
        """
        if not data or len(data) < block_size:
            return {
                "total_entropy": self.calculate_entropy(data),
                "blocks": [],
                "high_entropy_blocks": 0,
                "is_uniformly_encrypted": False
            }

        blocks = []
        high_entropy_count = 0

        for i in range(0, len(data) - block_size + 1, block_size):
            block = data[i:i + block_size]
            block_entropy = self.calculate_entropy(block)
            is_high = block_entropy > self.entropy_threshold

            blocks.append({
                "offset": i,
                "size": len(block),
                "entropy": round(block_entropy, 4),
                "is_high_entropy": is_high
            })

            if is_high:
                high_entropy_count += 1

        total_blocks = len(blocks)
        is_uniformly_encrypted = (
            total_blocks > 0 and
            high_entropy_count / total_blocks > 0.8
        )

        return {
            "total_entropy": round(self.calculate_entropy(data), 4),
            "blocks": blocks[:20],  # 最多返回 20 个块的信息
            "high_entropy_blocks": high_entropy_count,
            "total_blocks": total_blocks,
            "is_uniformly_encrypted": is_uniformly_encrypted
        }

    def detect_encryption_type(self, data: bytes) -> Optional[str]:
        """
        尝试识别加密类型
        基于数据特征推断
        """
        if not data or len(data) < 16:
            return None

        entropy = self.calculate_entropy(data)

        # 低熵：可能为明文或简单编码
        if entropy < 4.0:
            return "plaintext"

        # 中等熵：可能为 Base64 编码
        if 4.0 <= entropy < 6.0:
            # Base64 字符集检查
            try:
                text = data.decode("ascii", errors="strict")
                import re
                if re.match(r'^[A-Za-z0-9+/=\n]+$', text):
                    return "base64"
            except UnicodeDecodeError:
                pass
            return "compressed_or_encoded"

        # 高熵：可能为加密数据
        if entropy >= 6.0:
            # AES 块对齐检测
            if self.check_aes_alignment(data):
                return "aes_encrypted"

            # 检查是否为 XOR 加密（字节分布相对均匀）
            byte_counts = Counter(data)
            max_count = max(byte_counts.values())
            min_count = min(byte_counts.values())
            if max_count - min_count < len(data) * 0.1:
                return "xor_or_stream_cipher"

            return "encrypted_or_compressed"

        return None

    def calculate_ic(self, data: bytes) -> float:
        """
        计算重合指数（Index of Coincidence）
        用于区分随机数据和加密数据
        IC 接近 0.0385 表示随机，接近 0.065 表示英文文本
        """
        if len(data) < 2:
            return 0.0

        byte_counts = Counter(data)
        n = len(data)

        ic = sum(count * (count - 1) for count in byte_counts.values())
        ic /= n * (n - 1)

        return ic

    def sliding_window_entropy(
        self,
        data: bytes,
        window_size: int = 256,
        step: int = 64
    ) -> List[Tuple[int, float]]:
        """
        滑动窗口熵值计算
        用于检测数据中的加密区域
        返回 [(offset, entropy), ...]
        """
        results = []

        for i in range(0, len(data) - window_size + 1, step):
            window = data[i:i + window_size]
            entropy = self.calculate_entropy(window)
            results.append((i, round(entropy, 4)))

        return results

    def get_entropy_report(self, data: bytes) -> dict:
        """
        生成完整的熵值分析报告
        """
        if not data:
            return {
                "data_size": 0,
                "entropy": 0.0,
                "is_high_entropy": False,
                "is_aes_aligned": False,
                "encryption_type": None,
                "ic": 0.0
            }

        entropy = self.calculate_entropy(data)
        ic = self.calculate_ic(data)
        encryption_type = self.detect_encryption_type(data)
        is_aes = self.check_aes_alignment(data)

        report = {
            "data_size": len(data),
            "entropy": round(entropy, 4),
            "is_high_entropy": entropy > self.entropy_threshold,
            "is_aes_aligned": is_aes,
            "encryption_type": encryption_type,
            "ic": round(ic, 6),
            "entropy_threshold": self.entropy_threshold
        }

        # 对较大数据进行分块分析
        if len(data) >= 64:
            block_analysis = self.analyze_blocks(data)
            report["block_analysis"] = block_analysis

        return report
