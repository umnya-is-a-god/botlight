<?php

/**
 * IPv4 range arithmetic for the subnet calculator: ranges are [first, last]
 * pairs of integers (ip2long), results are CIDR strings.
 */
class Calc
{
    // sort and join overlapping or adjacent ranges
    public function alignment(array $arr): array
    {
        usort($arr, fn ($a, $b) => $a[0] <=> $b[0]);
        $r = [];
        foreach ($arr as $v) {
            $last = count($r) - 1;
            if ($last >= 0 && $v[0] <= $r[$last][1] + 1) {
                $r[$last][1] = max($r[$last][1], $v[1]);
            } else {
                $r[] = $v;
            }
        }
        return $r;
    }

    // range $a without range $b: zero, one or two ranges
    public function substract(array $a, array $b): array
    {
        if ($b[1] < $a[0] || $b[0] > $a[1]) {
            return [$a];
        }
        $r = [];
        if ($b[0] > $a[0]) {
            $r[] = [$a[0], $b[0] - 1];
        }
        if ($b[1] < $a[1]) {
            $r[] = [$b[1] + 1, $a[1]];
        }
        return $r;
    }

    // included ranges minus every excluded range
    public function prepare(array $include, array $exclude): array
    {
        $r = $this->alignment($include);
        foreach ($this->alignment($exclude) as $e) {
            $next = [];
            foreach ($r as $v) {
                $next = array_merge($next, $this->substract($v, $e));
            }
            $r = $next;
        }
        return $r;
    }

    // the fewest CIDR blocks covering exactly [$a, $b]
    public function toCIDR(int $a, int $b): array
    {
        $r = [];
        while ($a <= $b) {
            // the largest block aligned at $a that does not pass $b
            $size = 32;
            while ($size > 0) {
                $block = 1 << (33 - $size);
                if ($a % $block != 0 || $a + $block - 1 > $b) {
                    break;
                }
                $size--;
            }
            $r[] = long2ip($a) . "/$size";
            $a += 1 << (32 - $size);
        }
        return $r;
    }
}
