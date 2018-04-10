#include "settings.h"

class FDR
{
    public:
        FDR(char op, int operand);
        char getOperator();
        int getOperand();
        void setOperator(char op);
        void setOperand(int operand);

    private:
        char _operator;
        int _operand;
};