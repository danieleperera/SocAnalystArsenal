def printTable(tbl, borderHorizontal='-', borderVertical='|', borderCross='+'):
    cols = [list(x) for x in zip(*tbl)]
    lengths = [max(map(len, map(str, col))) for col in cols]
    f = borderVertical + borderVertical.join(' {:>%d} ' % l for l in lengths) + borderVertical
    s = borderCross + borderCross.join(borderHorizontal * (l+2) for l in lengths) + borderCross

    print(s)
    for row in tbl:
        print(f.format(*row))
        print(s)


x = [
    ['test', ''], 
    [0, 0], 
    [250, 6], 
    [500, 21], 
    [750, 50], 
    [1000, 87], 
    [1250, 135], 
    [1500, 196], 
    [1750, 269], 
    [2000, 351]
    ]

printTable(x)