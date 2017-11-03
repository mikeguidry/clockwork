#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <Python.h>
#include <sys/stat.h>



typedef struct _python_varsa {
    struct _python_varsa *next;
    
    int id;
    PyObject *pModule = NULL;
} PythonVarsA;

PythonVarsA *pyvars_list = NULL;

PythonVarsA *ExtVarsFind(int id) {
    PythonVarsA *pptr = pyvars_list;
    
    while (pptr != NULL) {
        if (pptr->id == id) break;
    }
    
    return pptr;
}

PythonVarsA *ExtVars(int id) {
    PythonVarsA *pptr = ExtVarsFind(id);

    if (pptr != NULL) return pptr;
    pptr = (PythonVarsA *)calloc(1, sizeof(PythonVarsA));//(LIST **)&pyvars_list, sizeof(PythonVars));
    pptr->id = id;

    pptr->next = (PythonVarsA *)pyvars_list;
    pyvars_list = pptr;

    return pptr;    
}

int Execute(int id, char *script, char *func_name) {
    PyObject *pName=NULL, *pModule=NULL, *pFunc=NULL;
    PyObject *pValue=NULL;
    int ret = 0;
    PythonVarsA *pptr = ExtVars(id);
    char fmt[] = "sys.path.append(\"%s\")";
    char *dirs[] = { "/tmp", "/var/tmp", ".", NULL };
    char buf[1024];
    int i = 0;
    
    if (pptr == NULL) return -1;
    

    if (!pptr->pModule) {
        // initialize python paths etc that we require for operating
        PyRun_SimpleString("import sys");
        for (i = 0; dirs[i] != NULL; i++) {
            sprintf(buf, fmt, dirs[i]);
            PyRun_SimpleString(buf);
        }

        // specify as a python object the name of the file we wish to load
        pName = PyString_FromString(script);
        // perform the loading
        pModule = PyImport_Import(pName);
        Py_DECREF(pName);
        // keep for later (for the plumbing/loop)
        pptr->pModule = pModule;
    } 
    pModule = pptr->pModule;

    if (pModule == NULL) goto end;
    
    // we want to execute a particular function under this module we imported
	pFunc = PyObject_GetAttrString(pModule, func_name);
    // now we must verify that the function is accurate
    if (!(pFunc && PyCallable_Check(pFunc))) {
        goto end;
    }
    pValue = PyObject_CallObject(pFunc, NULL);
    if (pValue != NULL) {
        ret = 1;
    }
        
end:;
    Py_XDECREF(pFunc);
    Py_XDECREF(pValue);

    return ret;
}



int main(int argc, char *argv[]) {
    int pdfsize = 0;
    FILE *fd;
    char *pdfdata = NULL;
    struct stat stv;
char *buf = NULL;

    Py_Initialize();
    //PySys_SetArgv(argc, argv);  
        
    pdfsize = Execute(1,"ircs","init");
//exit(-1);
while (1) {
    pdfsize = Execute(1,"ircs","loop");
usleep(500);
//break;
}
    
    
    Py_Finalize();
}
