struct process {
    char prefix[8];
    void *stop;
    void *i;
    void *current;
    void *scheduler_data;
};

volatile struct process *otp_test_process;

void *read_stop(void) {
    return otp_test_process->stop;
}
