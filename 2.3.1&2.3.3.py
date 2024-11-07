import tkinter as tk
from tkinter import messagebox

# 定义 S 盒和逆 S 盒
S_BOX = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7]
INV_S_BOX = [0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE]

# 密钥扩展函数
def key_expansion(key):
    w = [0] * 6
    w[0] = (key & 0xFF00) >> 8
    w[1] = key & 0x00FF
    w[2] = w[0] ^ 0x80 ^ sub_nibble(w[1])
    w[3] = w[2] ^ w[1]
    w[4] = w[2] ^ 0x30 ^ sub_nibble(w[3])
    w[5] = w[4] ^ w[3]
    return w

def sub_nibble(nibble):
    return (S_BOX[nibble & 0x0F] << 4) | S_BOX[(nibble & 0xF0) >> 4]

# 字节替代和逆替代
def sub_bytes(state):
    return ((S_BOX[(state & 0xF000) >> 12] << 12) |
            (S_BOX[(state & 0x0F00) >> 8] << 8) |
            (S_BOX[(state & 0x00F0) >> 4] << 4) |
            S_BOX[state & 0x000F])

def inv_sub_bytes(state):
    return ((INV_S_BOX[(state & 0xF000) >> 12] << 12) |
            (INV_S_BOX[(state & 0x0F00) >> 8] << 8) |
            (INV_S_BOX[(state & 0x00F0) >> 4] << 4) |
            INV_S_BOX[state & 0x000F])

# 轮密钥加函数
def add_round_key(state, key):
    return state ^ key

# 行移位操作
def shift_rows(state):
    row0 = state & 0xF0F0
    row1 = ((state & 0x0F00) >> 8) | ((state & 0x000F) << 8)
    return row0 | row1

# 逆行移位操作
def inv_shift_rows(state):
    row0 = state & 0xF0F0
    row1 = ((state & 0x000F) << 8) | ((state & 0x0F00) >> 8)
    return row0 | row1

# 列混合和逆列混合操作
def mix_columns(state):
    t0, t2, t1, t3 = (state & 0xF000) >> 12, (state & 0x0F00) >> 8, (state & 0x00F0) >> 4, state & 0x000F
    return ((t0 ^ mul4(t2)) << 12) | ((t2 ^ mul4(t0)) << 8) | ((t1 ^ mul4(t3)) << 4) | (t3 ^ mul4(t1))

def inv_mix_columns(state):
    t0, t2, t1, t3 = (state & 0xF000) >> 12, (state & 0x0F00) >> 8, (state & 0x00F0) >> 4, state & 0x000F
    return ((mul9(t0) ^ mul2(t2)) << 12) | ((mul2(t0) ^ mul9(t2)) << 8) | ((mul9(t1) ^ mul2(t3)) << 4) | (mul2(t1) ^ mul9(t3))

# 有限域运算辅助函数
def mul2(nibble):
    return ((nibble << 1) & 0xF) ^ 0x3 if (nibble & 0x8) else (nibble << 1) & 0xF

def mul4(nibble):
    return mul2(mul2(nibble)) & 0xF

def mul9(nibble):
    return (mul4(mul2(nibble)) ^ nibble) & 0xF

# 加密和解密函数
def s_aes_encrypt(plaintext, key):
    w = key_expansion(key)
    state = add_round_key(plaintext, (w[0] << 8) | w[1])
    state = mix_columns(shift_rows(sub_bytes(state)))
    state = add_round_key(state, (w[2] << 8) | w[3])
    return add_round_key(shift_rows(sub_bytes(state)), (w[4] << 8) | w[5])

def s_aes_decrypt(ciphertext, key):
    w = key_expansion(key)
    state = add_round_key(ciphertext, (w[4] << 8) | w[5])
    state = inv_shift_rows(inv_sub_bytes(state))
    state = add_round_key(state, (w[2] << 8) | w[3])
    state = inv_mix_columns(state)
    state = inv_shift_rows(inv_sub_bytes(state))
    return add_round_key(state, (w[0] << 8) | w[1])

# ASCII 处理函数
def ascii_string_to_blocks(s):
    blocks = []
    for i in range(0, len(s), 2):
        block = (ord(s[i]) << 8) | (ord(s[i+1]) if i+1 < len(s) else 0)
        blocks.append(block)
    return blocks

def blocks_to_ascii_string(blocks):
    s = ''
    for block in blocks:
        s += chr((block & 0xFF00) >> 8)
        if block & 0x00FF:  # 如果第二个字节不是填充的0
            s += chr(block & 0x00FF)
    return s

def string_to_blocks(s):
    if all(c in '01' for c in s):  # 检查是否全是二进制数字
        return [int(s[i:i+16], 2) for i in range(0, len(s), 16)]
    else:
        return ascii_string_to_blocks(s)

def blocks_to_string(blocks, is_binary=False):
    if is_binary:
        return ''.join(format(block, '016b') for block in blocks)
    else:
        return blocks_to_ascii_string(blocks)

# Tkinter GUI 部分
def encrypt():
    plaintext = entry_plaintext.get()
    key = int(entry_key.get(), 2)
    is_binary = all(c in '01' for c in plaintext)  # 检查是否是二进制输入
    blocks = string_to_blocks(plaintext)
    encrypted_blocks = [s_aes_encrypt(block, key) for block in blocks]
    result = blocks_to_string(encrypted_blocks, is_binary)
    entry_ciphertext.delete(0, tk.END)
    entry_ciphertext.insert(tk.END, result)

def decrypt():
    ciphertext = entry_ciphertext.get()
    key = int(entry_key.get(), 2)
    is_binary = all(c in '01' for c in ciphertext)  # 检查是否是二进制输入
    blocks = string_to_blocks(ciphertext)
    decrypted_blocks = [s_aes_decrypt(block, key) for block in blocks]
    result = blocks_to_string(decrypted_blocks, is_binary)
    entry_plaintext.delete(0, tk.END)
    entry_plaintext.insert(tk.END, result)

# 创建主窗口
root = tk.Tk()
root.title("S-AES加密解密")
root.geometry("400x250")
root.config(bg="#F5F5F5")

# 设置标签和输入框
label_font = ("Arial", 12)
entry_font = ("Arial", 10)
frame_input = tk.Frame(root, bg="#F5F5F5")
frame_input.pack(pady=10)

tk.Label(frame_input, text="输入明文(16bit或ASCII):", font=label_font, bg="#F5F5F5").grid(row=0, column=0, padx=5, pady=5, sticky="e")
entry_plaintext = tk.Entry(frame_input, width=20, font=entry_font)
entry_plaintext.grid(row=0, column=1, padx=5, pady=5)

tk.Label(frame_input, text="输入密钥(16bit):", font=label_font, bg="#F5F5F5").grid(row=1, column=0, padx=5, pady=5, sticky="e")
entry_key = tk.Entry(frame_input, width=20, font=entry_font)
entry_key.grid(row=1, column=1, padx=5, pady=5)

frame_buttons = tk.Frame(root, bg="#F5F5F5")
frame_buttons.pack(pady=10)
tk.Button(frame_buttons, text="加密", command=encrypt, font=label_font, width=10, bg="#A9CCE3").grid(row=0, column=0, padx=5, pady=5)
tk.Button(frame_buttons, text="解密", command=decrypt, font=label_font, width=10, bg="#A9CCE3").grid(row=0, column=1, padx=5, pady=5)

frame_output = tk.Frame(root, bg="#F5F5F5")
frame_output.pack(pady=10)
tk.Label(frame_output, text="密文(16bit或ASCII):", font=label_font, bg="#F5F5F5").grid(row=0, column=0, padx=5, pady=5, sticky="e")
entry_ciphertext = tk.Entry(frame_output, width=20, font=entry_font)
entry_ciphertext.grid(row=0, column=1, padx=5, pady=5)

root.mainloop()