import tkinter as tk
from tkinter import messagebox
import random

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

# CBC模式下的加密和解密
def cbc_encrypt(plaintext, key, iv):
    ciphertext_blocks = []
    prev_ciphertext = iv
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        if len(block) < 16:
            block += '0' * (16 - len(block))
        block = int(block, 2)
        block ^= prev_ciphertext
        ciphertext_block = s_aes_encrypt(block, key)
        ciphertext_blocks.append(ciphertext_block)
        prev_ciphertext = ciphertext_block
    return ciphertext_blocks

def cbc_decrypt(ciphertext_blocks, key, iv):
    plaintext_blocks = []
    prev_ciphertext = iv
    for ciphertext_block in ciphertext_blocks:
        block = s_aes_decrypt(ciphertext_block, key)
        block ^= prev_ciphertext
        plaintext_blocks.append(format(block, '016b'))
        prev_ciphertext = ciphertext_block
    return ''.join(plaintext_blocks)

# Tkinter GUI 部分
def encrypt():
    try:
        plaintext = entry_plaintext.get().replace(' ', '')
        key = int(entry_key.get(), 2)
        iv = int(entry_iv.get(), 2)
        ciphertext_blocks = cbc_encrypt(plaintext, key, iv)
        ciphertext = ' '.join(format(block, '016b') for block in ciphertext_blocks)
        entry_ciphertext.delete(0, tk.END)
        entry_ciphertext.insert(tk.END, ciphertext)
    except ValueError as e:
        messagebox.showerror("输入错误", str(e))

def decrypt():
    try:
        ciphertext = entry_ciphertext.get().replace(' ', '')
        ciphertext_blocks = [int(ciphertext[i:i+16], 2) for i in range(0, len(ciphertext), 16)]
        key = int(entry_key.get(), 2)
        iv = int(entry_iv.get(), 2)
        plaintext = cbc_decrypt(ciphertext_blocks, key, iv)
        entry_plaintext.delete(0, tk.END)
        entry_plaintext.insert(tk.END, plaintext)
    except ValueError as e:
        messagebox.showerror("输入错误", str(e))

def tamper():
    try:
        ciphertext = entry_ciphertext.get().replace(' ', '')
        ciphertext_blocks = [int(ciphertext[i:i+16], 2) for i in range(0, len(ciphertext), 16)]
        block_index = int(entry_tamper_index.get())
        tampered_bit = int(entry_tamper_bit.get())
        if block_index >= len(ciphertext_blocks):
            messagebox.showerror("输入错误", "块索引超出范围")
            return
        ciphertext_blocks[block_index] ^= (1 << tampered_bit)
        tampered_ciphertext = ' '.join(format(block, '016b') for block in ciphertext_blocks)
        entry_ciphertext.delete(0, tk.END)
        entry_ciphertext.insert(tk.END, tampered_ciphertext)
    except ValueError as e:
        messagebox.showerror("输入错误", str(e))

# 创建主窗口
root = tk.Tk()
root.title("S-AES CBC加密解密")
root.geometry("600x450")
root.config(bg="#F5F5F5")

# 设置标签和输入框
label_font = ("Arial", 12)
entry_font = ("Arial", 10)
frame_input = tk.Frame(root, bg="#F5F5F5")
frame_input.pack(pady=10)

tk.Label(frame_input, text="输入明文(16bit分组):", font=label_font, bg="#F5F5F5").grid(row=0, column=0, padx=5, pady=5, sticky="e")
entry_plaintext = tk.Entry(frame_input, width=40, font=entry_font)
entry_plaintext.grid(row=0, column=1, padx=5, pady=5)

tk.Label(frame_input, text="输入密钥(16bit):", font=label_font, bg="#F5F5F5").grid(row=1, column=0, padx=5, pady=5, sticky="e")
entry_key = tk.Entry(frame_input, width=20, font=entry_font)
entry_key.grid(row=1, column=1, padx=5, pady=5)

tk.Label(frame_input, text="输入初始向量(16bit):", font=label_font, bg="#F5F5F5").grid(row=2, column=0, padx=5, pady=5, sticky="e")
entry_iv = tk.Entry(frame_input, width=20, font=entry_font)
entry_iv.grid(row=2, column=1, padx=5, pady=5)

frame_buttons = tk.Frame(root, bg="#F5F5F5")
frame_buttons.pack(pady=10)
tk.Button(frame_buttons, text="加密", command=encrypt, font=label_font, width=10, bg="#A9CCE3").grid(row=0, column=0, padx=5, pady=5)
tk.Button(frame_buttons, text="解密", command=decrypt, font=label_font, width=10, bg="#A9CCE3").grid(row=0, column=1, padx=5, pady=5)

frame_output = tk.Frame(root, bg="#F5F5F5")
frame_output.pack(pady=10)
tk.Label(frame_output, text="密文(16bit分组):", font=label_font, bg="#F5F5F5").grid(row=0, column=0, padx=5, pady=5, sticky="e")
entry_ciphertext = tk.Entry(frame_output, width=40, font=entry_font)
entry_ciphertext.grid(row=0, column=1, padx=5, pady=5)

frame_tamper = tk.Frame(root, bg="#F5F5F5")
frame_tamper.pack(pady=10)
tk.Label(frame_tamper, text="篡改块索引:", font=label_font, bg="#F5F5F5").grid(row=0, column=0, padx=5, pady=5, sticky="e")
entry_tamper_index = tk.Entry(frame_tamper, width=5, font=entry_font)
entry_tamper_index.grid(row=0, column=1, padx=5, pady=5)

tk.Label(frame_tamper, text="篡改位:", font=label_font, bg="#F5F5F5").grid(row=1, column=0, padx=5, pady=5, sticky="e")
entry_tamper_bit = tk.Entry(frame_tamper, width=5, font=entry_font)
entry_tamper_bit.grid(row=1, column=1, padx=5, pady=5)

tk.Button(frame_tamper, text="篡改密文", command=tamper, font=label_font, width=10, bg="#A9CCE3").grid(row=2, column=0, columnspan=2, padx=5, pady=5)

root.mainloop()