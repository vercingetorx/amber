pub fn coprime_from_start(start: usize, limit: usize) -> usize {
    if limit <= 1 {
        return 1;
    }
    let mut candidate = start % limit;
    if candidate == 0 {
        candidate = 1;
    }
    while gcd(candidate, limit) != 1 {
        candidate = (candidate + 1) % limit;
        if candidate == 0 {
            candidate = 1;
        }
    }
    candidate
}

fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}
