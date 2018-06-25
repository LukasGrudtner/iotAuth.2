#ifndef FDR_H
#define FDR_H

#include <string>

class FDR
{
  public:
    char getOperator();
    int getOperand();
    void setOperator(char operating);
    void setOperand(int operand);

    int getValue(int argument);

    std::string toString();

  private:
    char operating = '+';
    int operand = 0;
};

#endif
