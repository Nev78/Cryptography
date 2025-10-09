def integer_kth_root(k, n):
    lo = 0
    hi = 1 << ((n.bit_length() + k - 1) // k + 1)
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if mid ** k <= n:
            lo = mid
        else:
            hi = mid
    return lo

def main():
    n = 30460296206281253605887131667441042408833105116654370140736576080711297109384941590369941855116386695157474206375705248890458232777575365270780855265861075198881090190505284920581410885950363830131451127387018904728639607372668753109249046707840464876881594185896506371262697868257217488062754637361594352910022190227237953540282162231147699265142164623465337280610190892470279654386272723760887111753067292988287956381022028725288845603024605833650847697724636088418782911705757980221361510892370739837402705040814150778298018509675199917931423568797098139493145394232981571448400646089157848498064505852923746440139
    e = 3
    ct = 183001753190025751114220069887230720857448492282044619321040127443487542179613757444809112210217896463899655491288132907560322811734646233820773

    pt = integer_kth_root(3, ct)

    if pt**3 != ct:
        print("Warning: ct is not an exact cube - possible problem")
    else:
        length = (pt.bit_length() + 7) // 8
        plaintext_bytes = pt.to_bytes(length, "big")
        try:
            plaintext = plaintext_bytes.decode("utf-8")
        except UnicodeDecodeError:
            plaintext = plaintext_bytes  

        #print("Decrypted message:", plaintext)

        with open("task-4-flag.txt", "w", encoding="utf-8") as f:
            if isinstance(plaintext, bytes):
                f.write(plaintext.hex())
            else:
                f.write(plaintext)
        print("Flag saved in task-4-flag.txt")

if __name__ == "__main__":
    main()
