#include "fdr.h"
#include <iostream>

/*  getOperator()
    Retorna o atributo 'operador' do objeto.
*/
char FDR::getOperator()
{
    return operating;
}

/*  getOperand()
    Retorna o atributo 'operando' do objeto.
*/
int FDR::getOperand()
{
    return operand;
}

/*  setOperator()
    Seta o atributo 'operador' do objeto com o valor recebido por parâmetro.
*/
void FDR::setOperator(char operating)
{
    this->operating = operating;
}

/*  setOperand()
    Seta o atributo 'operando' do objeto com o valor recebido por parâmetro.
*/
void FDR::setOperand(int operand)
{
    this->operand = operand;
}

/*  toString()
    Retorna uma representação da FDR em formato String.
*/
std::string FDR::toString()
{
    std::string result = operating + std::to_string(operand);
    return result;
}

int FDR::getValue(int argument)
{
    switch (getOperator())
    {
        case '+':
            return getOperand() + argument;
            break;
    
        default:
            break;
    }
}
