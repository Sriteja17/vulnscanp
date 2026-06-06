int main() {
    int val = 100;
    int *ptr = &val;
    *ptr = 200;
    return *ptr;
}
