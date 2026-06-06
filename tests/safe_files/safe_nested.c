int main() {
    int matrix[3][3];
    int i, j;
    for (i = 0; i < 3; i++) {
        for (j = 0; j < 3; j++) {
            matrix[i][j] = i + j;
        }
    }
    return matrix[1][1];
}
