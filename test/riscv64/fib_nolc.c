int rec(int n) {    
    if (n <= 0)    
        return 1;    
    return n + rec(n - 1);     
}    
     
__attribute__((force_align_arg_pointer))    
void _start() {    
    int n = 5;    
    int res = rec(n);    
    asm("lb a0, %0\n"    
        "li a7, 93\n"    
        "ecall\n" :: "m"(res)    
    );      
    __builtin_unreachable();    
}    

