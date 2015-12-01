
//  Queue.h
//  This file implements a doubly linked list (Queue)
//  The "queued items" are pointers to items that are the queued objects, 
//  so the queued items can be in multiple queues. 
//  NOTE: IT is the programmers responsibility to ensure that
//  no item is in multiple queues at the time a queue destructor is called.
//  If that happens then a queued item is destroyed but another queue still
//  points to released memory and bad things happen.
//    W. Boyer Oct 2002
//  
//  (it allows for inserting at the tail and
//  removing from the head or in the middle)
//   NOTE: The function source code is implemented in this header
//   file because the linker could not handle linking
//   with templates.
// 
//  
#ifndef QUEUE_H
#define QUEUE_H
#include <iostream>
using std::cout;
using std::endl;
#include <assert.h>
//#include <new.h>

//enum bool {false, true}; // for hpux

template <class Type> class Queue;

template <class Type>
class QueueItem {
 public:
  friend class Queue<Type>;

 // template <class T>
    //friend  ostream& operator<<(ostream& os,QueueItem<T>& qi);

  QueueItem( Type &t )  { item = &t; next = 0; prev=0;}
 private:
  Type *item;
  QueueItem *next;
  QueueItem *prev;
};

template <class Type> 
class Queue {

 public:
   //template <class T>
   //friend ostream& operator<<(ostream& os ,Queue<T>& q);

    Queue() { front = back = current = 0; qsize=0;}
    void clearQ() {
        // note: this can be a recursive function if
        // there is a Queue of Queues 
        while (current = front ) {
             front = current->next;
	     delete current->item;
             delete current;
        }
	qsize =0;
	back = 0;
    }    

    ~Queue(){
       clearQ();
    }

    Type* remove(QueueItem<Type> *it)
    {
       Type* retval;
         // assume "it" is an item in this queue
       assert (it !=0);

       QueueItem<Type> *pt1, *pt2; 
       pt1 = it->prev;
       pt2 = it->next;
       current = pt2;
       if (pt1 == 0) front = pt2;
       else pt1->next = pt2;
       if (pt2 == 0) back = pt1;
       else pt2->prev = pt1;
       retval = it->item;
       delete it;
       qsize--;
       return retval;
    }

    bool remove_item(Type *itm)
    {
        assert (itm !=0);
        bool r_val = false;
        current = front;
        while ( current ) {
            if (current->item == itm) {
                r_val = remove( current);
		return r_val;
            }
            current = current->next;
        }
        return r_val;
    }
    
    bool remove_current_item()
    {
        return remove( current);;	
    }


    Type* removeHead()
    {
        Type *rval;
	if (front == 0) {
		rval = 0;
        }
        else {
	  rval = remove(front);
        }
        return rval;
    }

    void dump()
    {
        front =0;
        back = 0;
        qsize = 0;
    }

    void emptyQ() 
    {
       // empty the queue without deleting queued items
           while ( current = front ) {
              front = current->next;
              delete current;
           }
	   back =0;
	   qsize =0;
    }    
         
    Type* getnext()
    {
        Type *rval;
        if (current == 0) rval = 0;
        else {
          QueueItem<Type> *pt = current->next;
          current = pt;
          if (pt == 0) rval = 0;
          else   rval = pt->item;
        }
        return rval;
    }

    Type* getprev()
    {
        Type *rval;
        if (current == 0) rval = 0;
        else {
          QueueItem<Type> *pt = current->prev;
          current = pt;
          if (pt == 0) rval = 0;
          else   rval = pt->item;
        }
        return rval;
    }

    Type* gethead()
    {
        Type* rval;
        QueueItem<Type> *pt = front;
	current = pt;
        if (pt == 0) rval =0;
        else rval = pt->item;
        return rval;
    }
    
    Type* gettail()
    {
        Type* rval;
        QueueItem<Type> *pt = back;
	current = pt;
        if (pt == 0) rval =0;
        else rval = pt->item;
        return rval;
    }
  
   QueueItem<Type>* add( Type &val)
   {  
     assert( &val != 0);
     // allocate a new QueueItem object  
     QueueItem<Type> *pt =  
        new QueueItem<Type>( val ); 
     assert( pt != NULL);
     if (pt != 0) {
       if ( front == 0 ) 
         front = back = pt; 
       else { 
         back->next = pt; 
	 pt->prev = back;
         back = pt; 
       }
       current = pt;
       qsize ++;
     }
     return pt;
   }

   bool add_alloc( Type &val, char *buf)
   {   // add in pre-allocated buffer area
       QueueItem<Type> *pt =
       new (buf) QueueItem<Type>( val );
       assert( pt != NULL);

       if ( front == 0 )
         front = back = pt;
       else {
         back->next = pt;
	 pt->prev = back;
         back = pt;
       }
       current = pt;
       qsize ++;

       return true;
   }


   QueueItem<Type>* getCurrentQitem()
   {
      return current;
   }

   QueueItem<Type>* getheadQitem()
   {
      current = front;
      return front;
   }

   QueueItem<Type>* getnextQitem(QueueItem<Type>* qi)
   {
      QueueItem<Type>* rval;
         current = qi->next;
         rval = current;
      return current;
   }

   QueueItem<Type>* getprevQitem(QueueItem<Type>* qi)
   {
      QueueItem<Type>* rval;
         current = qi->prev;
         rval = current;
      return current;
   }

   Type* getitem(QueueItem<Type>* qi)
   {
      Type* rval;
      if (qi == 0) rval = 0;
      else rval = qi->item;
      return rval;
   }

    bool is_empty() { 
        return front==0 ? true : false; }

    int size() {
        return qsize;
    }
    
    bool audit() {
       int count =0;
       bool rval = true;
       QueueItem<Type> *curr, *previous;
       previous = 0;
       for (curr = front; curr; curr= curr->next)
       {
            count++;
	    if (curr->prev != previous) {
	        rval = false;
                cout << "Queue prev pointer error\n";		
            }
            previous = curr;
       }
       if ( back != previous)
       {
	    rval = false;
            cout << "Queue back pointer error\n";		
       }
       if (count != qsize) {
           rval = false;
 	   cout << "Queue length ERROR\n"; 
       }
       return rval;
    }
    
    void move ( Queue & newQ)
    {
         newQ.emptyQ();
         newQ.front = front;
         newQ.back = back;		 
	 newQ.current = current;
	 newQ.qsize = qsize;
	 dump();
    }
    
    void copy ( Queue & newQ)
    {
         newQ.emptyQ();
	 Type *ptr = gethead();   
	 while (ptr != 0) {
             newQ.add(*ptr); 
	     ptr = getnext();
         }
    }
    
    void exchange (QueueItem<Type> &i1, QueueItem<Type> &i2)
    {
         Type *ptr = i1.item;
         i1.item = i2.item;    
	 i2.item = ptr;
    }
    
    bool contains( Type *it)
    {
         if (front ==0) return false;
	 current = front;
	 while(current){
              if(it == current->item)
		      return true;
	      current = current->next;
	 }
	 return false;
    }
    
    QueueItem<Type>* insert(QueueItem<Type> *it, Type &val )
    {
       //  insert new item (val) PRECEDING "it".
         // assume "it" is an item in this queue or null
         // if "it" is null insert at end of queue
       QueueItem<Type> *pt1, *pt; 
       assert( &val != 0);
       if (it == 0 || front == 0) {
           return add(val);	       
       }
       pt1 = it->prev;
       pt = new QueueItem<Type>(val);
       assert( pt != NULL);
       if (pt != 0) {
              current = pt;
	      pt->prev = pt1;
              it->prev = pt;
              pt->next = it;
              if (pt1 == 0) front = pt;
                  else pt1->next = pt;
              qsize++;
       }
       return pt;
    }
    
    QueueItem<Type>* insert_item(Type &it, Type &val )
    {
        // insert val preceding it
	 current = front;
	 while(current && (current->item != &it) ){
	      current = current->next;
	 }
	 return insert(current, val);
    }

    void cat(  Queue<Type> &q2)
    {
	// concat q2 to tail of this queue     
        if (q2.qsize == 0) return;
	if (qsize != 0){
	   back->next = q2.front;
	   q2.front->prev = back;
	}    
	else {
	   front = q2.front;	
        }
	back = q2.back;
        qsize += q2.qsize; 	    
	q2.front=0;
	q2.back=0;
	q2.current=0;
	q2.qsize=0;
    }

private:
    QueueItem<Type> *front; 
    QueueItem<Type> *back;
    QueueItem<Type> *current;
    int qsize;
};
#endif
