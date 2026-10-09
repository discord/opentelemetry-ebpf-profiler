// Tiny DWARF fixture for the BEAM Process offset reader.
struct process {
    char prefix[8];
    void *stop;
    void *frame_pointer;
    void *i;
    void *current;
    void *scheduler_data;
};

volatile struct process *otp_test_process;

struct ErtsSchedulerData_ {
    char prefix[32];
    void *current_process;
    void *current_nif;
};

volatile struct ErtsSchedulerData_ *otp_test_scheduler;

void *read_stop(void) {
    return otp_test_process->stop;
}

void *read_current_nif(void) {
    return otp_test_scheduler->current_nif;
}

void *read_current_process(void) {
    return otp_test_scheduler->current_process;
}

void *read_scheduler_data(void) {
    return otp_test_process->scheduler_data;
}

typedef struct {
    struct {
        char prefix[16];
        void *call_bif_nif;
    } trampoline;
    void *mfa;
    int argc;
} ErtsNativeFunc;

volatile ErtsNativeFunc *otp_test_native_func;

void *read_native_func_mfa(void) {
    return otp_test_native_func->mfa;
}

void *read_native_func_trampoline(void) {
    return otp_test_native_func->trampoline.call_bif_nif;
}
